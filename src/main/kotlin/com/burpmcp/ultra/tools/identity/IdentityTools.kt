package com.burpmcp.ultra.tools.identity

import com.burpmcp.ultra.core.IdentityStore
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

/**
 * Identity Matrix MCP surface (2.5.0): import/inspect the identity registry.
 * Applying identities to requests lives on http_send_request / http_fuzz /
 * idor_hunt / access_control_sweep via their `identity` parameter.
 */
object IdentityTools {
    fun register(server: Server) {
        server.addTool(
            name = "identity_import",
            description = "Import an Identity Matrix registry (schema: identity/identity-matrix.schema.json, v4). " +
                "Provide the registry either inline (registry_json) or from a file (registry_path). " +
                "Optionally pass secrets: a map of credential id -> resolved secret value (the manager side owns " +
                "vault resolution; Burp never reads vault:// itself). Validates structure and cross-layer referential " +
                "integrity before installing; on failure the previous registry is kept.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("registry_json") { put("type", "string"); put("description", "Registry JSON, inline") }
                    putJsonObject("registry_path") { put("type", "string"); put("description", "Path to a registry JSON file") }
                    putJsonObject("secrets") {
                        put("type", "object")
                        put("description", "Optional map credential id -> secret value, resolved by the manager")
                        putJsonObject("additionalProperties") { put("type", "string") }
                    }
                },
                required = emptyList() // one of registry_json / registry_path
            )
        ) { request ->
            try {
                val a = request.params.arguments ?: emptyMap()
                val secrets = a["secrets"]?.jsonObject?.mapValues { (_, v) -> v.jsonPrimitive.contentOrNull ?: "" } ?: emptyMap()
                val json = a["registry_json"]?.jsonPrimitive?.contentOrNull
                    ?: a["registry_path"]?.jsonPrimitive?.contentOrNull?.let { path ->
                        try {
                            java.nio.file.Files.readString(java.nio.file.Path.of(path))
                        } catch (e: Exception) {
                            return@addTool err("Cannot read registry_path '$path': ${e.message}")
                        }
                    }
                    ?: return@addTool err("Provide registry_json or registry_path")
                CallToolResult(content = listOf(TextContent(IdentityStore.import(json, secrets).toString())))
            } catch (e: Exception) {
                err(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "identity_list",
            description = "List identities from the imported registry with their credentials, injection surface, " +
                "secret readiness, binding mode and session states.",
            inputSchema = ToolSchema(properties = buildJsonObject { }, required = emptyList())
        ) { _ ->
            CallToolResult(content = listOf(TextContent(IdentityStore.list().toString())))
        }

        server.addTool(
            name = "identity_status",
            description = "Deep status of one identity: full definition plus its live sessions with timing.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("identity") { put("type", "string"); put("description", "Identity id, e.g. id:persona-1") }
                },
                required = listOf("identity")
            )
        ) { request ->
            try {
                val id = request.params.arguments?.get("identity")?.jsonPrimitive?.contentOrNull
                    ?: return@addTool err("Parameter 'identity' is required")
                CallToolResult(content = listOf(TextContent(IdentityStore.status(id).toString())))
            } catch (e: Exception) {
                err(e.message ?: "Unknown error")
            }
        }
    }

    private fun err(msg: String): CallToolResult =
        CallToolResult(content = listOf(TextContent(buildJsonObject { put("error", msg) }.toString())), isError = true)
}
