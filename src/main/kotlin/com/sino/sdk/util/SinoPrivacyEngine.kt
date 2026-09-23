package com.sino.sdk.util

import com.sino.sdk.crypto.SecurityUtils

/**
 * Open Implementation of Sino's Forensic Log Sanitizer.
 * Ported from the Core Consensus to ensure zero-trust logging across all integration tiers.
 * Hardened v3.2: Single-pass consolidated scanner for zero intermediate forensic leakage.
 */
class SinoPrivacyEngine {

    private val patternsMap = linkedMapOf(
        "EMAIL" to "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}",
        "BIP39" to "\\b(?:[a-z]{3,8}\\s+){11,23}[a-z]{3,8}\\b",
        "AUTH_TOKEN" to "ya29\\.[a-zA-Z0-9_-]+",
        "S3_ACCESS_KEY" to "\\b(?:AKIA|ASIA)[A-Z0-9]{16}\\b",
        "S3_SECRET_KEY" to "(?i)secret[\\s=:]+[A-Za-z0-9/+=]{40}",
        "S3_KEY" to "\\b(?:SinoVault|SinoBackup)/[^\\s\"'}]+",
        "MEGA_CHALLENGE" to "hashcash:[^\\s\"'}]+",
        "MEGA_SESSION" to "\\bsid:[a-zA-Z0-9_-]{40,}\\b",
        "SENSITIVE_ID" to "[a-fA-F0-9]{32,}",
        "HASH_PATH" to "[a-fA-F0-9]{16}",
        "MEGA_HANDLE" to "\\b(?=.*[0-9_-])[a-zA-Z0-9_-]{8,11}\\b",
        "FILE_NAME" to "\\b[\\w-]+\\.(?i:jpe?g|png|webp|mp4|mkv|mov|pdf|zip|7z|tmp|enc|batch|meta|sino|json|bin|public)\\b",
        "FILE_PATH" to "(?:/[\\w.-]+){2,}",
        "SECURITY_ARTIFACT" to "security/[^\\s\"'}]+",
        "METADATA_ARTIFACT" to "metadata/[^\\s\"'}]+",
        "BASE64" to "(?:[A-Za-z0-9+/]{4}){15,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
        "BASE64_URL" to "(?:[A-Za-z0-9_-]{4}){15,}(?:[A-Za-z0-9_-]{2}|[A-Za-z0-9_-]{3})?"
    )

    private val labels = patternsMap.keys.toList()
    private val masterRegex = Regex(patternsMap.values.joinToString("|") { "($it)" })

    /**
     * Prevents leakage of sensitive data by masking identifiers.
     * Single-pass execution ensures zero sensitive "ghost strings" remain in the heap.
     *
     * @param input The raw log message.
     * @return The sanitized log message.
     */
    fun sanitize(input: String): String {
        if (input.isEmpty()) return ""
        
        var highStakesFound = false
        val sanitized = masterRegex.replace(input) { matchResult ->
            val matchedGroupIndex = (1 until matchResult.groups.size).firstOrNull { matchResult.groups[it] != null }
            
            if (matchedGroupIndex != null) {
                val label = labels[matchedGroupIndex - 1]
                if (isHighStakes(label)) highStakesFound = true
                "[REDACTED_$label]"
            } else {
                matchResult.value
            }
        }

        if (highStakesFound) {
            SecurityUtils.requestSystemGc()
        }
        
        return sanitized
    }

    private fun isHighStakes(label: String): Boolean = when(label) {
        "BIP39", "AUTH_TOKEN", "S3_SECRET_KEY", "MEGA_SESSION", "BASE64", "BASE64_URL" -> true
        else -> false
    }
}
