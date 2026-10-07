package com.burpmcp.ultra.core

import kotlinx.serialization.json.*

/**
 * In-memory store for the Identity Matrix registry (identity/identity-matrix.schema.json,
 * schema v4). Layer model: credentials (secret material + injection target) →
 * identities (ordered credential sets) → bindings (pool/dedicated) → sessions.
 *
 * Secrets are NOT stored in the registry — only `secret_ref` vault pointers.
 * The manager side resolves them and passes a credentialId→value map to
 * [import]. Applying an identity whose credential has no resolved secret is an
 * error, never a partial injection (atomicity contract).
 */
object IdentityStore {

    data class Injection(val credentialId: String, val inject: String, val name: String)

    @Volatile private var registry: JsonObject? = null
    private val secrets = mutableMapOf<String, String>()

    val hasRegistry: Boolean get() = registry != null

    fun reset() {
        registry = null
        synchronized(secrets) { secrets.clear() }
    }

    /**
     * Validates and installs a registry. Structural checks (kind consts,
     * required fields per layer) plus referential integrity across layers.
     * Returns either errors (registry unchanged) or an import summary.
     */
    fun import(jsonText: String, secretMap: Map<String, String> = emptyMap()): JsonObject {
        val root = try { Json.parseToJsonElement(jsonText) } catch (e: Exception) {
            return err("Registry is not valid JSON: ${e.message}")
        }
        if (root !is JsonObject) return err("Registry root must be a JSON object")

        val errors = mutableListOf<String>()
        val credentials = layer(root, "credentials", "credential", errors,
            required = listOf("type", "scope", "secret_ref", "lifecycle"))
        val identities = layer(root, "identities", "identity", errors, required = listOf("credentials"))
        // Bindings are anonymous in schema v4 (identified by pool / identity),
        // so unlike other layers they carry no id.
        val bindings = layer(root, "bindings", "binding", errors, required = emptyList(), requireId = false)
        val sessions = layer(root, "sessions", "session", errors, required = emptyList())

        val credIds = credentials.map { it.id }.toSet()
        val idIds = identities.map { it.id }.toSet()

        for (identity in identities) {
            val creds = identity.obj["credentials"]?.jsonArrayOrNull()?.mapNotNull { it.jsonPrimitiveOrNull()?.contentOrNull } ?: emptyList()
            if (creds.isEmpty()) errors.add("${identity.id}: credentials list is empty")
            creds.filter { it !in credIds }.forEach { errors.add("${identity.id}: references unknown credential '$it'") }
            val precedence = identity.obj["precedence"]?.jsonArrayOrNull()?.mapNotNull { it.jsonPrimitiveOrNull()?.contentOrNull } ?: emptyList()
            precedence.filter { it !in creds }.forEach { errors.add("${identity.id}: precedence entry '$it' is not in its credentials") }
        }
        for (binding in bindings) {
            val members = binding.obj["identities"]?.jsonArrayOrNull()?.mapNotNull { it.jsonPrimitiveOrNull()?.contentOrNull } ?: emptyList()
            if (members.isEmpty() && binding.obj["identity"] == null)
                errors.add("${binding.id ?: "binding"}: neither identities[] nor identity set")
            members.filter { it !in idIds }.forEach { errors.add("binding references unknown identity '$it'") }
            val mode = binding.obj["mode"]?.jsonPrimitiveOrNull()?.contentOrNull
            if (mode != null && mode != "shared" && mode != "dedicated")
                errors.add("binding mode '$mode' must be shared|dedicated")
        }
        for (session in sessions) {
            val fromCred = session.obj["from_credential"]?.jsonPrimitiveOrNull()?.contentOrNull
            if (fromCred != null && fromCred !in credIds) errors.add("${session.id}: unknown from_credential '$fromCred'")
            val identity = session.obj["identity"]?.jsonPrimitiveOrNull()?.contentOrNull
            if (identity != null && identity !in idIds) errors.add("${session.id}: unknown identity '$identity'")
        }

        if (errors.isNotEmpty()) return buildJsonObject {
            put("ok", false)
            put("errors", JsonArray(errors.map { JsonPrimitive(it) }))
            put("note", "Registry NOT installed; previous registry (if any) is unchanged.")
        }

        registry = root
        synchronized(secrets) {
            secrets.clear()
            secrets.putAll(secretMap)
        }
        return buildJsonObject {
            put("ok", true)
            put("credentials", credentials.size)
            put("identities", identities.size)
            put("bindings", bindings.size)
            put("sessions", sessions.size)
            put("secrets_provided", secretMap.size)
        }
    }

    /** One line per identity: id, credential count, inject surface, binding mode, session states. */
    fun list(): JsonObject {
        val reg = registry ?: return err("No registry imported; call identity_import first")
        val credById = items(reg, "credentials").associateBy { it.id }
        val bindingOf = mutableMapOf<String, String>()
        for (b in items(reg, "bindings")) {
            val mode = b.obj["mode"]?.jsonPrimitiveOrNull()?.contentOrNull ?: "?"
            val members = b.obj["identities"]?.jsonArrayOrNull()?.mapNotNull { it.jsonPrimitiveOrNull()?.contentOrNull } ?: emptyList()
            val single = b.obj["identity"]?.jsonPrimitiveOrNull()?.contentOrNull
            (members + listOfNotNull(single)).forEach { bindingOf[it] = mode }
        }
        val sessionStates = items(reg, "sessions").groupBy(
            { it.obj["identity"]?.jsonPrimitiveOrNull()?.contentOrNull ?: "?" },
            { it.obj["state"]?.jsonPrimitiveOrNull()?.contentOrNull ?: "?" }
        )
        return buildJsonObject {
            put("ok", true)
            put("identities", JsonArray(items(reg, "identities").map { identity ->
                buildJsonObject {
                    put("id", identity.id)
                    put("credentials", JsonArray(
                        (identity.obj["credentials"]?.jsonArrayOrNull()?.mapNotNull { it.jsonPrimitiveOrNull()?.contentOrNull } ?: emptyList())
                            .map { cid -> buildJsonObject {
                                put("id", cid)
                                put("type", credById[cid]?.obj?.get("type")?.jsonPrimitiveOrNull()?.contentOrNull ?: "?")
                                put("inject", credById[cid]?.obj?.get("application")?.jsonObjectOrNull()
                                    ?.get("inject")?.jsonPrimitiveOrNull()?.contentOrNull ?: "?")
                                put("secret_ready", synchronized(secrets) { cid in secrets })
                            } }
                    ))
                    put("binding_mode", bindingOf[identity.id] ?: "unbound")
                    put("session_states", JsonArray((sessionStates[identity.id] ?: emptyList()).distinct().map { JsonPrimitive(it) }))
                }
            }))
        }
    }

    /** Deep status for one identity: credential lifecycle, renewal summary, sessions with timing. */
    fun status(identityId: String): JsonObject {
        val reg = registry ?: return err("No registry imported; call identity_import first")
        val identity = items(reg, "identities").firstOrNull { it.id == identityId }
            ?: return err("Unknown identity '$identityId'; see identity_list")
        return buildJsonObject {
            put("ok", true)
            put("identity", identity.obj)
            put("sessions", JsonArray(items(reg, "sessions")
                .filter { it.obj["identity"]?.jsonPrimitiveOrNull()?.contentOrNull == identityId }
                .map { it.obj }))
        }
    }

    /**
     * Resolves the ordered injection plan for an identity (precedence order if
     * present, else credentials order). Fails with a missing-secret list instead
     * of returning a partial plan.
     */
    fun resolveInjections(identityId: String): Any {
        val reg = registry ?: return err("No registry imported; call identity_import first")
        val identity = items(reg, "identities").firstOrNull { it.id == identityId }
            ?: return err("Unknown identity '$identityId'; see identity_list")
        val credIds = identity.obj["credentials"]?.jsonArrayOrNull()?.mapNotNull { it.jsonPrimitiveOrNull()?.contentOrNull } ?: emptyList()
        val precedence = identity.obj["precedence"]?.jsonArrayOrNull()?.mapNotNull { it.jsonPrimitiveOrNull()?.contentOrNull } ?: emptyList()
        val order = precedence.ifEmpty { credIds }
        val credById = items(reg, "credentials").associateBy { it.id }

        val plan = mutableListOf<Injection>()
        val missing = mutableListOf<String>()
        for (cid in order) {
            val cred = credById[cid] ?: return err("Identity references unknown credential '$cid' (registry corrupt)")
            val app = cred.obj["application"]?.jsonObjectOrNull()
            val inject = app?.get("inject")?.jsonPrimitiveOrNull()?.contentOrNull ?: continue
            if (inject == "tls" || inject == "signer") continue // transport-layer, not request-layer injection
            val name = app?.get("name")?.jsonPrimitiveOrNull()?.contentOrNull
                ?: if (inject == "bearer") "Authorization" // bearer targets a fixed header
                else return err("Credential '$cid' injects via '$inject' but has no application.name")
            val secret = synchronized(secrets) { secrets[cid] }
            if (secret == null) { missing += cid; continue }
            plan += Injection(cid, inject, name)
        }
        return if (missing.isEmpty()) buildJsonObject {
            put("ok", true)
            put("injections", JsonArray(plan.map {
                buildJsonObject { put("credential", it.credentialId); put("inject", it.inject); put("name", it.name) }
            }))
        } else err("No secret materialized for: ${missing.joinToString()}. " +
            "Pass them via identity_import secrets (credential id -> value); the manager owns vault resolution. " +
            "Nothing was injected.")
    }

    fun secretFor(credentialId: String): String? = synchronized(secrets) { secrets[credentialId] }

    // ------------------------------------------------------------------

    private data class LayerItem(val id: String?, val obj: JsonObject)

    private fun layer(
        root: JsonObject, arrayName: String, kind: String, errors: MutableList<String>, required: List<String>,
        requireId: Boolean = true
    ): List<LayerItem> {
        val element = root[arrayName] ?: return emptyList()
        val array = element.jsonArrayOrNull() ?: run { errors.add("'$arrayName' must be an array"); return emptyList() }
        val seen = mutableSetOf<String>()
        return array.mapNotNull { item ->
            val obj = item as? JsonObject
            if (obj == null) { errors.add("$arrayName entry is not an object"); return@mapNotNull null }
            val itemKind = obj["kind"]?.jsonPrimitiveOrNull()?.contentOrNull
            if (itemKind != kind) errors.add("$arrayName entry kind '$itemKind' != '$kind'")
            val id = obj["id"]?.jsonPrimitiveOrNull()?.contentOrNull
            if (id == null && requireId) errors.add("$arrayName entry has no id")
            else if (id != null && !seen.add(id)) errors.add("duplicate id '$id' in $arrayName")
            required.filter { obj[it] == null }.forEach { errors.add("$arrayName entry '${id ?: kind}' misses required '$it'") }
            LayerItem(id, obj)
        }
    }

    private fun items(root: JsonObject, arrayName: String): List<LayerItem> =
        (root[arrayName] as? JsonArray)?.mapNotNull { (it as? JsonObject)?.let { o -> LayerItem(o["id"]?.jsonPrimitiveOrNull()?.contentOrNull, o) } } ?: emptyList()

    private fun err(msg: String): JsonObject = buildJsonObject { put("ok", false); put("error", msg) }
}

private fun JsonElement.jsonArrayOrNull(): JsonArray? = this as? JsonArray
private fun JsonElement.jsonObjectOrNull(): JsonObject? = this as? JsonObject
private fun JsonElement.jsonPrimitiveOrNull(): JsonPrimitive? = this as? JsonPrimitive
