package com.burpmcp.ultra.core

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.contentOrNull

/**
 * Natural-name alias mapping for tool arguments. Callers (LLM agents) often use
 * generic field names like `title` or `description`; without this mapping those
 * values were silently dropped because only the canonical name was read.
 *
 * Resolution order: canonical name first, then aliases left to right.
 */
object ArgumentAliases {

    private val findingAliases: Map<String, List<String>> = mapOf(
        "type" to listOf("vuln_type", "issue_type"),
        "url" to listOf("target", "affected_url"),
        "detail" to listOf("description", "summary", "title"),
        "evidence" to listOf("proof", "payload"),
        "steps_to_reproduce" to listOf("reproduce_steps", "steps"),
        "cvss_score" to listOf("score"),
        "owasp_category" to listOf("owasp"),
        "request" to listOf("raw_request"),
        "response" to listOf("raw_response"),
    )

    fun resolveFindingArgs(args: Map<String, JsonElement>): Map<String, String> =
        findingAliases.mapValues { (canonical, aliases) ->
            (listOf(canonical) + aliases).firstNotNullOfOrNull { name ->
                args[name]?.jsonPrimitive?.contentOrNull?.takeIf { it.isNotBlank() }
            } ?: ""
        }

    /** Returns human-readable notes about which aliases were consumed, e.g. "description -> detail". */
    fun applied(args: Map<String, JsonElement>): List<String> =
        findingAliases.mapNotNull { (canonical, aliases) ->
            val canonicalPresent = args[canonical]?.jsonPrimitive?.contentOrNull?.isNotBlank() == true
            val used = aliases.firstOrNull { alias ->
                !canonicalPresent && args[alias]?.jsonPrimitive?.contentOrNull?.isNotBlank() == true
            }
            used?.let { "$it -> $canonical" }
        }
}
