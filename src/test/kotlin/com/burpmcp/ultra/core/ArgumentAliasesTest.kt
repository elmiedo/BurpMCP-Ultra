package com.burpmcp.ultra.core

import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ArgumentAliasesTest {

    @Test fun `description alias fills detail`() {
        val resolved = ArgumentAliases.resolveFindingArgs(buildJsonObject {
            put("type", "xss"); put("url", "http://x/"); put("description", "reflected in q")
        })
        assertEquals("reflected in q", resolved["detail"])
        assertEquals("xss", resolved["type"])
    }

    @Test fun `title alias fills detail when description absent`() {
        val resolved = ArgumentAliases.resolveFindingArgs(buildJsonObject {
            put("type", "sqli"); put("url", "http://x/"); put("title", "SQLi in search")
        })
        assertEquals("SQLi in search", resolved["detail"])
    }

    @Test fun `canonical detail wins over aliases`() {
        val resolved = ArgumentAliases.resolveFindingArgs(buildJsonObject {
            put("type", "idor"); put("url", "http://x/"); put("detail", "canonical"); put("title", "alias")
        })
        assertEquals("canonical", resolved["detail"])
    }

    @Test fun `applied reports consumed aliases and not canonical names`() {
        val applied = ArgumentAliases.applied(buildJsonObject {
            put("type", "xss"); put("url", "http://x/"); put("description", "d"); put("summary", "s")
        })
        assertEquals(listOf("description -> detail"), applied)
    }

    @Test fun `applied is empty when only canonical names used`() {
        val applied = ArgumentAliases.applied(buildJsonObject {
            put("type", "xss"); put("url", "http://x/"); put("detail", "d")
        })
        assertTrue(applied.isEmpty())
    }

    @Test fun `missing fields resolve to blank but type and url presence is detectable`() {
        val resolved = ArgumentAliases.resolveFindingArgs(buildJsonObject { put("detail", "only detail") })
        assertEquals("", resolved["type"])
        assertEquals("", resolved["url"])
        assertEquals("only detail", resolved["detail"])
    }
}
