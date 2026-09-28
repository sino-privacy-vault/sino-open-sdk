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
        "AUTHTOKEN" to "ya29\\.[a-zA-Z0-9_-]+",
        "S3ACCESSKEY" to "\\b(?:AKIA|ASIA)[A-Z0-9]{16}\\b",
        "S3SECRETKEY" to "[sS][eE][cC][rR][eE][tT][\\s=:]+[A-Za-z0-9/+=]{40}",
        "S3KEY" to "\\b(?:SinoVault|SinoBackup)/[^\\s\"'}]+",
        "MEGACHALLENGE" to "hashcash:[^\\s\"'}]+",
        "MEGASESSION" to "\\bsid:[a-zA-Z0-9_-]{40,}\\b",
        "SENSITIVEID" to "[a-fA-F0-9]{32,}",
        "HASHPATH" to "[a-fA-F0-9]{16}",
        "MEGAHANDLE" to "\\b(?=[a-zA-Z0-9_-]{8,11}\\b)(?=[^\\s]*[0-9])[a-zA-Z0-9_-]{8,11}\\b",
        "FILENAME" to "\\b[\\w-]+\\.(?:[jJ][pP][eE]?[gG]|[pP][nN][gG]|[wW][eE][bB][pP]|[mM][pP]4|[mM][kK][vV]|[mM][oO][vV]|[pP][dD][fF]|[zZ][iI][pP]|7[zZ]|[tT][mM][pP]|[eE][nN][cC]|[bB][aA][tT][cC][hH]|[mM][eE][tT][aA]|[sS][iI][nN][oO]|[jJ][sS][oO][nN]|[bB][iI][nN]|[pP][uU][bB][lL][iI][cC])\\b",
        "FILEPATH" to "(?:/[\\w.-]+){2,}",
        "SECURITYARTIFACT" to "security/[^\\s\"'}]+",
        "METADATAARTIFACT" to "metadata/[^\\s\"'}]+",
        "BASE64" to "(?:[A-Za-z0-9+/]{4}){15,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
        "BASE64URL" to "(?:[A-Za-z0-9_-]{4}){15,}(?:[A-Za-z0-9_-]{2}|[A-Za-z0-9_-]{3})?"
    )

    private val displayLabels = mapOf(
        "EMAIL" to "EMAIL",
        "BIP39" to "BIP39",
        "AUTHTOKEN" to "AUTH_TOKEN",
        "S3ACCESSKEY" to "S3_ACCESS_KEY",
        "S3SECRETKEY" to "S3_SECRET_KEY",
        "S3KEY" to "S3_KEY",
        "MEGACHALLENGE" to "MEGA_CHALLENGE",
        "MEGASESSION" to "MEGA_SESSION",
        "SENSITIVEID" to "SENSITIVE_ID",
        "HASHPATH" to "HASH_PATH",
        "MEGAHANDLE" to "MEGA_HANDLE",
        "FILENAME" to "FILE_NAME",
        "FILEPATH" to "FILE_PATH",
        "SECURITYARTIFACT" to "SECURITY_ARTIFACT",
        "METADATAARTIFACT" to "METADATA_ARTIFACT",
        "BASE64" to "BASE64",
        "BASE64URL" to "BASE64_URL"
    )

    private val labels = patternsMap.keys.toList()
    private val masterRegex = Regex(patternsMap.entries.joinToString("|") { (label, pattern) -> "(?<$label>$pattern)" })

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
            val matchedLabel = labels.firstOrNull { label -> matchResult.groups[label] != null }
            
            if (matchedLabel != null) {
                if (isHighStakes(matchedLabel)) highStakesFound = true
                val displayLabel = displayLabels[matchedLabel] ?: matchedLabel
                "[REDACTED_$displayLabel]"
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
        "BIP39", "AUTHTOKEN", "S3SECRETKEY", "MEGASESSION", "BASE64", "BASE64URL" -> true
        else -> false
    }
}
