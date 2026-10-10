#!/usr/bin/env python3
"""Async MCP client for BurpMCP-Ultra's SSE transport.

Manager-side production seam: everything the manager needs to drive the Burp
extension programmatically — establish the SSE session, call tools, read
responses off the stream. Uses httpx so the same client class serves both the
MCP control channel and (via a separate instance) per-identity data traffic.

Usage:
    async with BurpMcpClient("http://127.0.0.1:9876", token) as c:
        ver = await c.call("burp_version")
        for t in await c.list_tools(): ...
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Optional

import httpx


class McpError(RuntimeError):
    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(f"MCP error {code}: {message}")
        self.code, self.message, self.data = code, message, data


class BurpMcpClient:
    def __init__(self, base_url: str, token: str,
                 client: Optional[httpx.AsyncClient] = None):
        self.base = base_url.rstrip("/")
        self.token = token
        self._client = client          # injected for tests / shared pools
        self._owns_client = client is None
        self.session_id: Optional[str] = None
        self._pending: dict[int, asyncio.Future] = {}
        self._reader_task: Optional[asyncio.Task] = None
        self._id = 0

    # ── lifecycle ────────────────────────────────────────────────────────────

    async def __aenter__(self) -> "BurpMcpClient":
        await self.connect()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    async def connect(self) -> None:
        if self._owns_client:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(10, read=600))
        # Open the SSE stream; Ultra answers the first event with the session id.
        self._sse_response = await self._client.send(
            self._client.build_request(
                "GET", f"{self.base}/sse",
                headers={"Authorization": f"Bearer {self.token}",
                         "Accept": "text/event-stream"},
            ), stream=True)
        if self._sse_response.status_code != 200:
            body = (await self._sse_response.aread()).decode(errors="replace")[:200]
            raise ConnectionError(f"SSE {self._sse_response.status_code}: {body}")
        self._reader_task = asyncio.create_task(self._read_stream())
        deadline = asyncio.get_running_loop().time() + 10
        while self.session_id is None:
            if asyncio.get_running_loop().time() > deadline:
                raise TimeoutError("no endpoint event from SSE stream")
            await asyncio.sleep(0.05)

    async def close(self) -> None:
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except (asyncio.CancelledError, httpx.HTTPError):
                pass
        if self._sse_response is not None:
            await self._sse_response.aclose()
        if self._owns_client and self._client is not None:
            await self._client.aclose()

    # ── SSE reader ───────────────────────────────────────────────────────────

    async def _read_stream(self) -> None:
        event, data_lines = None, []
        try:
            async for raw in self._sse_response.aiter_lines():
                line = raw.rstrip("\r")
                if line == "":
                    if event is not None:
                        self._dispatch(event, "\n".join(data_lines))
                    event, data_lines = None, []
                elif line.startswith("event:"):
                    event = line[6:].strip()
                elif line.startswith("data:"):
                    data_lines.append(line[5:].lstrip())
        except httpx.HTTPError:
            pass  # stream torn down on close()

    def _dispatch(self, event: str, data: str) -> None:
        if event == "endpoint" and data.startswith("?sessionId="):
            self.session_id = data[len("?sessionId="):]
            return
        if event != "message":
            return
        try:
            msg = json.loads(data)
        except json.JSONDecodeError:
            return
        fut = self._pending.pop(msg.get("id"), None)
        if fut is not None and not fut.done():
            if "error" in msg and msg["error"] is not None:
                fut.set_exception(McpError(msg["error"].get("code", -1),
                                           msg["error"].get("message", "?"),
                                           msg["error"].get("data")))
            else:
                fut.set_result(msg.get("result"))

    # ── JSON-RPC ─────────────────────────────────────────────────────────────

    async def _rpc(self, method: str, params: dict) -> Any:
        if self.session_id is None:
            raise ConnectionError("not connected")
        self._id += 1
        rid = self._id
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[rid] = fut
        r = await self._client.post(
            f"{self.base}/?sessionId={self.session_id}",
            headers={"Authorization": f"Bearer {self.token}"},
            json={"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        if r.status_code not in (200, 202):
            raise ConnectionError(f"POST {method}: HTTP {r.status_code} {r.text[:200]}")
        return await asyncio.wait_for(fut, timeout=600)

    async def list_tools(self) -> list[dict]:
        res = await self._rpc("tools/list", {})
        return res.get("tools", [])

    async def call(self, tool: str, arguments: Optional[dict] = None) -> Any:
        """Returns the decoded tool result. Ultra returns content blocks;
        for text content returns the concatenated text, else the raw structure."""
        res = await self._rpc("tools/call", {"name": tool, "arguments": arguments or {}})
        if isinstance(res, dict) and res.get("isError"):
            texts = [c.get("text", "") for c in res.get("content", []) if c.get("type") == "text"]
            raise McpError(-32000, "tool error: " + " ".join(texts), res)
        content = res.get("content", []) if isinstance(res, dict) else []
        texts = [c.get("text", "") for c in content if c.get("type") == "text"]
        if len(texts) == 1:
            t = texts[0]
            try:
                return json.loads(t)
            except (json.JSONDecodeError, ValueError):
                return t
        return texts or res


# ── CLI smoke: python3 mcp_client.py <base_url> <token> [tool] [json_args] ──

async def _cli() -> None:
    import sys
    args = sys.argv[1:]
    base, token = args[0], args[1]
    async with BurpMcpClient(base, token) as c:
        if len(args) < 3:
            tools = await c.list_tools()
            print(f"connected, session={c.session_id}, tools={len(tools)}")
            return
        result = await c.call(args[2], json.loads(args[3]) if len(args) > 3 else {})
        print(json.dumps(result, ensure_ascii=False, indent=2)[:4000])

if __name__ == "__main__":
    asyncio.run(_cli())
