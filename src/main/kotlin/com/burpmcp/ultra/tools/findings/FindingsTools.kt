package com.burpmcp.ultra.tools.findings

import com.burpmcp.ultra.bridge.FindingsBridge
import com.burpmcp.ultra.bridge.Owasp2021
import com.burpmcp.ultra.core.ArgumentAliases
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

/**
 * Registers the findings-memory tools: `findings_add` (deduplicated) and
 * `findings_list`. Gives the agent persistent recall of confirmed/suspected
 * issues across a session for triage and reporting.
 */
object FindingsTools {
    fun register(server: Server, bridge: FindingsBridge) {
        server.addTool(
            name = "findings_add",
            description = "Record a confirmed or suspected finding in the agent's deduplicated findings store " +
                "(working memory, separate from Burp's scanner). Re-adding the same type+url+location is deduped. " +
                "Use to remember bugs you've confirmed so you can triage/report them later. " +
                "Fills the Findings tab in Burp (survives reloads).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("type") { put("type", "string"); put("description", "Vulnerability type, e.g. xss, sqli, idor, ssrf, info_leak") }
                    putJsonObject("severity") { put("type", "string"); put("description", "critical|high|medium|low|info (default info)") }
                    putJsonObject("url") { put("type", "string"); put("description", "Affected URL") }
                    putJsonObject("location") { put("type", "string"); put("description", "Where it lives: param:name, header:name, body, path") }
                    putJsonObject("detail") { put("type", "string"); put("description", "Description of the issue. Aliases accepted: description, summary, title") }
                    putJsonObject("evidence") { put("type", "string"); put("description", "Evidence (payload, response excerpt)") }
                    putJsonObject("cvss_score") { put("type", "string"); put("description", "CVSS base score, 0.0-10.0 (e.g. 8.1). Optional.") }
                    putJsonObject("cvss_vector") { put("type", "string"); put("description", "CVSS vector string (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H). Optional.") }
                    putJsonObject("owasp_category") {
                        put("type", "string")
                        put("description", "OWASP Top 10 2021 category. Accepts the code (A03), code+year (A03:2021), or the name (Injection, SSRF, broken access control) - normalized to canonical form. Optional. Valid: ${Owasp2021.validValues()}")
                    }
                    putJsonObject("steps_to_reproduce") { put("type", "string"); put("description", "Numbered steps to reproduce the issue. Optional.") }
                    putJsonObject("request") { put("type", "string"); put("description", "Raw HTTP request evidence (the triggering request). Optional.") }
                    putJsonObject("response") { put("type", "string"); put("description", "Raw HTTP response evidence (the proof response). Optional.") }
                },
                required = listOf("type", "url")
            )
        ) { request ->
            try {
                val a = request.params.arguments ?: emptyMap()
                val resolved = ArgumentAliases.resolveFindingArgs(a)
                val type = resolved["type"]?.takeIf { it.isNotBlank() } ?: return@addTool err("Parameter 'type' is required")
                val url = resolved["url"]?.takeIf { it.isNotBlank() } ?: return@addTool err("Parameter 'url' is required")
                val result = bridge.add(
                    type,
                    resolved["severity"] ?: "info",
                    url,
                    resolved["location"] ?: "",
                    resolved["detail"] ?: "",
                    resolved["evidence"] ?: "",
                    resolved["cvss_score"] ?: "",
                    resolved["cvss_vector"] ?: "",
                    resolved["owasp_category"] ?: "",
                    resolved["steps_to_reproduce"] ?: "",
                    resolved["request"] ?: "",
                    resolved["response"] ?: ""
                )
                // Surface alias usage so natural field names (title/description) are
                // never consumed silently.
                val resultWithAliases = if (ArgumentAliases.applied(a).isEmpty()) result else buildJsonObject {
                    result.forEach { (k, v) -> put(k, v) }
                    put("aliases_applied", JsonArray(ArgumentAliases.applied(a).map { JsonPrimitive(it) }))
                }
                CallToolResult(content = listOf(TextContent(resultWithAliases.toString())))
            } catch (e: Exception) {
                err(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "findings_list",
            description = "List the recorded findings, optionally filtered by severity and/or type.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("severity") { put("type", "string"); put("description", "Filter by severity") }
                    putJsonObject("type") { put("type", "string"); put("description", "Filter by type") }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val a = request.params.arguments ?: emptyMap()
                val result = bridge.list(a["severity"]?.jsonPrimitive?.contentOrNull, a["type"]?.jsonPrimitive?.contentOrNull)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                err(e.message ?: "Unknown error")
            }
        }
    }

    private fun err(msg: String): CallToolResult =
        CallToolResult(content = listOf(TextContent(buildJsonObject { put("error", msg) }.toString())), isError = true)
}
