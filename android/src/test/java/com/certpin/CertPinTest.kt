package com.certpin

import java.time.LocalDate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class CertPinTest {
    @Test
    fun parseValidRecord() {
        val spki = "spki".encodeToByteArray()
        val fp = CertPin.spkiFingerprintBase64(spki)
        val record = "v=CERTPIN1; fp=$fp; exp=2026-12-31; ttl=3600"

        val policy = CertPin.parse(record)

        assertEquals("CERTPIN1", policy.version)
        assertEquals(listOf(fp), policy.fingerprints)
        assertEquals(3600, policy.ttlSeconds)
        assertEquals(LocalDate.parse("2026-12-31"), policy.exp)
    }

    @Test
    fun parseFailsWithoutVersion() {
        assertFailsWith<CertPinParseException> {
            CertPin.parse("fp=Zm9v")
        }
    }

    @Test
    fun evaluateMatch() {
        val spki = "spki".encodeToByteArray()
        val fp = CertPin.spkiFingerprintBase64(spki)
        val record = "v=CERTPIN1; fp=$fp"

        val decision = CertPin.evaluate(record, spki)
        assertEquals(CertPinDecision.Match, decision)
    }

    @Test
    fun evaluateExpiredAsNoPolicy() {
        val spki = "spki".encodeToByteArray()
        val fp = CertPin.spkiFingerprintBase64(spki)
        val record = "v=CERTPIN1; fp=$fp; exp=2020-01-01"

        val decision = CertPin.evaluate(record, spki, LocalDate.parse("2026-01-01"))
        assertEquals(CertPinDecision.NoPolicy, decision)
    }
}
