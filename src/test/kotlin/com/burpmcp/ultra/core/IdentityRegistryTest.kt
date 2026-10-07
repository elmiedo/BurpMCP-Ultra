package com.burpmcp.ultra.core

import kotlinx.serialization.json.Json
import org.junit.jupiter.api.BeforeEach
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class IdentityRegistryTest {

    @BeforeEach fun resetStore() = IdentityStore.reset()

    private val registry = """
    {
      "credentials": [
        {"kind":"credential","id":"cred:cookie","type":"session-cookie","scope":{"hosts":["*.example.com"]},
         "secret_ref":"vault://kv/web1","application":{"inject":"cookie","name":"SID"},
         "lifecycle":{"status":"active"}},
        {"kind":"credential","id":"cred:key","type":"api-key","scope":{"hosts":["api.example.com"]},
         "secret_ref":"vault://kv/k1","application":{"inject":"header","name":"X-Key"},
         "lifecycle":{"status":"active"}},
        {"kind":"credential","id":"cred:jwt","type":"bearer-jwt","scope":{"hosts":["*.example.com"]},
         "secret_ref":"vault://kv/j","application":{"inject":"bearer"},
         "lifecycle":{"status":"active"}}
      ],
      "identities": [
        {"kind":"identity","id":"id:p1","credentials":["cred:cookie","cred:key","cred:jwt"],
         "precedence":["cred:jwt","cred:cookie"]}
      ],
      "bindings": [
        {"kind":"binding","mode":"shared","pool":"pool-A","identities":["id:p1"],"strategy":"sticky"}
      ],
      "sessions": [
        {"kind":"session","id":"sess:1","from_credential":"cred:cookie","identity":"id:p1","state":"live"}
      ]
    }
    """

    @Test fun `import accepts a valid registry and counts layers`() {
        val r = IdentityStore.import(registry)
        assertEquals("true", r["ok"].toString().let { Json.parseToJsonElement(it).toString() })
        assertTrue(r.toString().contains("\"credentials\":3"))
        assertTrue(r.toString().contains("\"identities\":1"))
        assertTrue(IdentityStore.hasRegistry)
    }

    @Test fun `import rejects broken JSON and keeps previous registry`() {
        IdentityStore.import(registry)
        val r = IdentityStore.import("{ not json")
        assertTrue(r.toString().contains("not valid JSON"))
        assertTrue(IdentityStore.hasRegistry, "previous registry must survive a failed import")
    }

    @Test fun `referential integrity across layers is enforced`() {
        val broken = registry
            .replace("\"cred:cookie\",\"cred:key\",\"cred:jwt\"", "\"cred:cookie\",\"cred:ghost\"")
            .replace("\"precedence\":[\"cred:jwt\",\"cred:cookie\"]", "\"precedence\":[\"cred:key\"]")
        val r = IdentityStore.import(broken)
        assertFalse(r.toString().contains("\"ok\":true"))
        assertTrue(r.toString().contains("unknown credential 'cred:ghost'"))
        assertTrue(r.toString().contains("precedence entry 'cred:key' is not in its credentials"))
    }

    @Test fun `missing required fields and duplicate ids are rejected`() {
        val bad = """{"credentials":[
            {"kind":"credential","id":"c1","type":"api-key","scope":{"hosts":["a"]},"secret_ref":"vault://x"},
            {"kind":"credential","id":"c1","type":"api-key","scope":{"hosts":["a"]},"secret_ref":"vault://x","lifecycle":{"status":"active"}}]}"""
        val r = IdentityStore.import(bad)
        assertTrue(r.toString().contains("misses required 'lifecycle'"))
        assertTrue(r.toString().contains("duplicate id 'c1'"))
    }

    @Test fun `resolveInjections honors precedence and reports missing secrets atomically`() {
        IdentityStore.import(registry)
        // No secrets provided: resolution must fail listing the plan's secretless
        // credentials (precedence members only — cred:key is outside the plan).
        val none = IdentityStore.resolveInjections("id:p1")
        assertTrue(none.toString().contains("No secret materialized"))
        assertTrue(none.toString().contains("cred:cookie"))
        assertTrue(none.toString().contains("cred:jwt"))
        assertFalse(none.toString().contains("cred:key"), "non-precedence credential is not part of the plan")

        IdentityStore.import(registry, mapOf("cred:cookie" to "xyz", "cred:jwt" to "tok"))
        val plan = IdentityStore.resolveInjections("id:p1")
        // Precedence puts jwt first; cred:key has no secret but is NOT in precedence,
        // so the plan over precedence members must succeed without it.
        assertTrue(plan.toString().contains("\"ok\":true"))
        assertTrue(plan.toString().indexOf("cred:jwt") < plan.toString().indexOf("cred:cookie"),
            "precedence order must be respected")
    }

    @Test fun `list and status reflect registry content`() {
        IdentityStore.import(registry)
        val list = IdentityStore.list().toString()
        assertTrue(list.contains("id:p1"))
        assertTrue(list.contains("secret_ready\":false"))
        val status = IdentityStore.status("id:p1").toString()
        assertTrue(status.contains("sess:1"))
        assertTrue(IdentityStore.status("id:ghost").toString().contains("Unknown identity"))
    }
}
