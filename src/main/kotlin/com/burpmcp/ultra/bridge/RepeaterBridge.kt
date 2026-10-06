package com.burpmcp.ultra.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.HttpService
import com.burpmcp.ultra.safety.RequestHygiene
import kotlinx.serialization.json.*

class RepeaterBridge(private val api: MontoyaApi) {

    fun sendToRepeater(
        request: String,
        host: String,
        port: Int,
        useTls: Boolean,
        tabName: String?,
        http2: Boolean = false
    ): JsonObject {
        val httpService = HttpService.httpService(host, port, useTls)
        // Normalize line endings so a bare-LF request doesn't fold into the HTTP/2
        // :path and land in Repeater "kettled" and unsendable (issue #7 request-line variant).
        val parsed = HttpRequest.httpRequest(httpService, RequestHygiene.normalizeCrlf(request))

        // For HTTP/2, rebuild the parsed HTTP/1 request as a native h2 request:
        // pseudo-headers are derived from the target, and hop-by-hop / framing
        // headers that are illegal in h2 (Connection, Transfer-Encoding, Host…)
        // are dropped — :authority replaces Host.
        val httpRequest = if (http2) {
            val authority = if (port == (if (useTls) 443 else 80)) host else "$host:$port"
            val pseudoHeaders = listOf(
                HttpHeader.httpHeader(":method", parsed.method()),
                HttpHeader.httpHeader(":path", parsed.path()),
                HttpHeader.httpHeader(":scheme", if (useTls) "https" else "http"),
                HttpHeader.httpHeader(":authority", authority)
            )
            val illegalInH2 = setOf(
                "connection", "keep-alive", "proxy-connection", "transfer-encoding",
                "upgrade", "host", "content-length"
            )
            val regular = parsed.headers().filter { it.name().lowercase() !in illegalInH2 }
            HttpRequest.http2Request(httpService, pseudoHeaders + regular, parsed.bodyToString())
        } else {
            parsed
        }

        if (tabName != null) {
            api.repeater().sendToRepeater(httpRequest, tabName)
        } else {
            api.repeater().sendToRepeater(httpRequest)
        }

        return buildJsonObject {
            put("tab_name", tabName ?: "auto")
            put("status", "created")
            put("host", host)
            put("port", port)
            put("use_tls", useTls)
            put("http2", http2)
        }
    }
}
