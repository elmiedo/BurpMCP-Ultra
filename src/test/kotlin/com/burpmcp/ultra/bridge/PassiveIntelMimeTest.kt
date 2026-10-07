package com.burpmcp.ultra.bridge

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PassiveIntelMimeTest {

    @Test fun `text content types are scannable`() {
        assertTrue(isTextBody("text/html; charset=utf-8"))
        assertTrue(isTextBody("application/json"))
        assertTrue(isTextBody("application/javascript;charset=UTF-8"))
        assertTrue(isTextBody("application/vnd.api+json"))
        assertTrue(isTextBody("application/atom+xml; charset=utf-8"))
        assertTrue(isTextBody(""))
    }

    @Test fun `binary content types are skipped`() {
        assertFalse(isTextBody("image/webp"))
        assertFalse(isTextBody("image/png"))
        assertFalse(isTextBody("font/woff2"))
        assertFalse(isTextBody("application/octet-stream"))
        assertFalse(isTextBody("application/zip"))
        assertFalse(isTextBody("video/mp4"))
    }

    @Test fun `splitHeaders separates header block from body`() {
        val msg = "HTTP/1.1 200 OK\r\nContent-Type: image/webp\r\n\r\nBINARYpg_"
        val (headers, body) = splitHeaders(msg)
        assertTrue(headers.endsWith("\r\n\r\n"))
        assertTrue(headers.contains("Content-Type"))
        assertEquals("BINARYpg_", body)
        assertEquals("", splitHeaders("no body here").second)
    }
}
