package com.certpin

import android.util.Base64
import java.security.MessageDigest
import java.time.LocalDate
import java.time.ZoneOffset
import java.time.format.DateTimeParseException

data class CertPinPolicy(
    val version: String,
    val fingerprints: List<String>,
    val exp: LocalDate?,
    val ttlSeconds: Long?,
)

sealed class CertPinDecision {
    data object NoPolicy : CertPinDecision()
    data object Match : CertPinDecision()
    data object Mismatch : CertPinDecision()
    data object Malformed : CertPinDecision()
}

class CertPinParseException(message: String) : IllegalArgumentException(message)

object CertPin {
    const val EXPECTED_VERSION: String = "CERTPIN1"

    @Throws(CertPinParseException::class)
    fun parse(record: String): CertPinPolicy {
        val normalized = normalizeRecord(record)
        if (normalized.isEmpty()) {
            throw CertPinParseException("Record is empty.")
        }

        var version: String? = null
        val fingerprints = mutableListOf<String>()
        var exp: LocalDate? = null
        var ttlSeconds: Long? = null

        normalized.split(';').forEach { rawPart ->
            val part = rawPart.trim()
            if (part.isEmpty()) return@forEach

            val equalsAt = part.indexOf('=')
            if (equalsAt <= 0 || equalsAt == part.lastIndex) {
                throw CertPinParseException("Malformed tag: $part")
            }

            val key = part.substring(0, equalsAt).trim().lowercase()
            val value = part.substring(equalsAt + 1).trim()

            when (key) {
                "v" -> {
                    if (version != null) {
                        throw CertPinParseException("Duplicate tag: v")
                    }
                    if (value != EXPECTED_VERSION) {
                        throw CertPinParseException("Invalid version: $value")
                    }
                    version = value
                }

                "fp" -> {
                    val decoded = decodeBase64(value)
                    if (decoded.size != 32) {
                        throw CertPinParseException("Invalid fp length (expected SHA-256 bytes): $value")
                    }
                    fingerprints += Base64.encodeToString(decoded, Base64.NO_WRAP)
                }

                "exp" -> {
                    if (exp != null) {
                        throw CertPinParseException("Duplicate tag: exp")
                    }
                    exp = try {
                        LocalDate.parse(value)
                    } catch (_: DateTimeParseException) {
                        throw CertPinParseException("Invalid exp date: $value")
                    }
                }

                "ttl" -> {
                    if (ttlSeconds != null) {
                        throw CertPinParseException("Duplicate tag: ttl")
                    }
                    val ttl = value.toLongOrNull()
                        ?: throw CertPinParseException("Invalid ttl: $value")
                    if (ttl <= 0) {
                        throw CertPinParseException("Invalid ttl: $value")
                    }
                    ttlSeconds = ttl
                }

                else -> throw CertPinParseException("Unknown tag: $key")
            }
        }

        if (version == null) {
            throw CertPinParseException("Missing required tag: v")
        }
        if (fingerprints.isEmpty()) {
            throw CertPinParseException("Missing required tag: fp")
        }

        return CertPinPolicy(
            version = version!!,
            fingerprints = fingerprints.toList(),
            exp = exp,
            ttlSeconds = ttlSeconds,
        )
    }

    fun spkiFingerprintBase64(spkiDer: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(spkiDer)
        return Base64.encodeToString(digest, Base64.NO_WRAP)
    }

    fun evaluate(
        record: String?,
        spkiDer: ByteArray,
        todayUtc: LocalDate = LocalDate.now(ZoneOffset.UTC),
    ): CertPinDecision {
        if (record == null || normalizeRecord(record).isEmpty()) {
            return CertPinDecision.NoPolicy
        }

        val policy = try {
            parse(record)
        } catch (_: CertPinParseException) {
            return CertPinDecision.Malformed
        }

        if (isExpired(policy, todayUtc)) {
            return CertPinDecision.NoPolicy
        }

        val presented = spkiFingerprintBase64(spkiDer)
        return if (policy.fingerprints.contains(presented)) {
            CertPinDecision.Match
        } else {
            CertPinDecision.Mismatch
        }
    }

    fun isExpired(policy: CertPinPolicy, todayUtc: LocalDate = LocalDate.now(ZoneOffset.UTC)): Boolean {
        val exp = policy.exp ?: return false
        return todayUtc.isAfter(exp)
    }

    private fun normalizeRecord(record: String): String {
        val trimmed = record.trim()
        return if (trimmed.length >= 2 && trimmed.startsWith("\"") && trimmed.endsWith("\"")) {
            trimmed.substring(1, trimmed.length - 1).trim()
        } else {
            trimmed
        }
    }

    private fun decodeBase64(value: String): ByteArray {
        return try {
            Base64.decode(value, Base64.DEFAULT)
        } catch (_: IllegalArgumentException) {
            throw CertPinParseException("Invalid fp base64: $value")
        }
    }
}
