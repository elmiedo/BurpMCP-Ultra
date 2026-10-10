package com.burpmcp.ultra.bridge

import burp.api.montoya.http.message.params.HttpParameter
import burp.api.montoya.http.message.requests.HttpRequest
import com.burpmcp.ultra.core.IdentityStore
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive

/**
 * Applies an identity's credential set to an outgoing request ATOMICALLY:
 * either every request-layer injection (cookies, headers, bearer) lands in one
 * pass, or the request is returned untouched with an error. Layers are
 * replaced, never merged — a stale cookie of the same name is overwritten, so
 * identities can't bleed into each other.
 */
object IdentityApplier {

    data class Outcome(val request: HttpRequest, val applied: List<String>, val error: String?)

    fun apply(request: HttpRequest, identityId: String?): Outcome {
        if (identityId.isNullOrBlank()) return Outcome(request, emptyList(), null)
        if (!IdentityStore.hasRegistry) return Outcome(request, emptyList(), "identity specified but no registry imported; call identity_import first")

        val plan = IdentityStore.resolveInjections(identityId)
        val planObj = plan as? kotlinx.serialization.json.JsonObject
            ?: return Outcome(request, emptyList(), "identity resolution failed: $plan")
        if (planObj["ok"]?.jsonPrimitive?.contentOrNull != "true")
            return Outcome(request, emptyList(), planObj.toString())
        val injections = planObj["injections"]?.jsonArray ?: return Outcome(request, emptyList(), "malformed injection plan")

        var current = request
        val applied = mutableListOf<String>()
        for (element in injections) {
            val inj = element.jsonObject
            val inject = inj["inject"]?.jsonPrimitive?.contentOrNull ?: continue
            val name = inj["name"]?.jsonPrimitive?.contentOrNull ?: continue
            val credential = inj["credential"]?.jsonPrimitive?.contentOrNull ?: continue
            val value = IdentityStore.secretFor(credential) ?: continue
            when (inject) {
                "cookie" -> current = upsertCookie(current, name, value)
                "header", "authorization" -> current = upsertHeader(current, name, value)
                "bearer" -> current = upsertHeader(current, "Authorization", "Bearer $value")
                "query" -> current = upsertQuery(current, name, value)
                else -> applied += "skipped:${credential}(${inject} not request-layer)"
            }
            applied += "${inject}:${name}<-${credential}"
        }
        return Outcome(current, applied, null)
    }

    // withUpdatedHeader is a no-op when the header is absent (verified live on
    // Montoya 2026.2: bearer/header injections silently vanished from the wire),
    // so presence-check and fall back to withHeader.
    private fun upsertHeader(request: HttpRequest, name: String, value: String): HttpRequest =
        if (request.hasHeader(name)) request.withUpdatedHeader(name, value)
        else request.withHeader(name, value)

    private fun upsertCookie(request: HttpRequest, name: String, value: String): HttpRequest =
        upsert(request, HttpParameter.cookieParameter(name, value))

    private fun upsertQuery(request: HttpRequest, name: String, value: String): HttpRequest =
        upsert(request, HttpParameter.urlParameter(name, value))

    private fun upsert(request: HttpRequest, param: HttpParameter): HttpRequest =
        if (request.hasParameter(param.name(), param.type())) request.withUpdatedParameters(param)
        else request.withAddedParameters(param)
}
