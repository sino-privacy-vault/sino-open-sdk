package com.sino.sdk.util

/**
 * Sino's log sanitizer, identical to the one every Sino platform runs: keeps PII and cryptographic material out of
 * persisted logs.
 * One consolidated regex, applied in a single pass.
 *
 * The pattern set errs on the side of redaction: a false positive costs a log detail, a false negative can leak a
 * key, credential or recovery phrase. At any position the *first* alternative that matches wins, so the
 * key=value and URL patterns come before the narrower token patterns they contain.
 */
class SinoPrivacyEngine {

    // Group names in Java Pattern must be strictly alphanumeric [a-zA-Z0-9].
    private val patternsMap = linkedMapOf(
        // key=value / key: value credentials, including JSON ("secretAccessKey":"..."). Redacts key and value.
        "CREDENTIAL" to "(?i)\\b(?:password|passwd|pwd|passphrase|pin|otp|mfa[_-]?code|[a-z_]*secret[a-z_]*|[a-z_]*token|" +
            "[a-z_]*key|dek|kek|rmk|dbk|authorization|session[_-]?id|sid|cookie)\\b[\"']?\\s*[:=]\\s*" +
            "(?:(?:bearer|basic)\\s+)?[\"']?[^\\s\"',;}&]+",
        // Whole URLs/URIs: presigned query strings carry credentials and paths carry bucket and file names.
        "URL" to "\\b[a-zA-Z][a-zA-Z0-9+.-]{1,15}://[^\\s\"'<>]+",
        "JWT" to "\\beyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*",
        "BEARER" to "(?i)\\b(?:bearer|basic)\\s+[A-Za-z0-9._~+/=-]{8,}",
        "PEM" to "-----BEGIN [A-Z ]+-----[\\s\\S]*?-----END [A-Z ]+-----",
        "EMAIL" to "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,63}",
        // 12-24 words of 3-8 letters, any case, separated by spaces/commas/semicolons, optionally numbered
        // ("1. abandon 2. ability ...").
        "BIP39" to "(?i)\\b(?:\\d{1,2}[.)]?\\s*)?[a-z]{3,8}(?:[\\s,;]+(?:\\d{1,2}[.)]?\\s*)?[a-z]{3,8}){11,23}\\b",
        "AUTHTOKEN" to "ya29\\.[a-zA-Z0-9_-]+",
        "S3ACCESSKEY" to "\\b(?:AKIA|ASIA)[A-Z0-9]{16}\\b",
        "S3SECRETKEY" to "[sS][eE][cC][rR][eE][tT][\\s=:]+[A-Za-z0-9/+=]{40}",
        "S3KEY" to "\\b(?:SinoVault|SinoBackup)/[^\\s\"'}]+",
        "MEGACHALLENGE" to "hashcash:[^\\s\"'}]+",
        "MEGASESSION" to "\\bsid:[a-zA-Z0-9_-]{40,}\\b",
        "SENSITIVEID" to "[a-fA-F0-9]{32,}",
        // Windows paths carry the account name (C:\Users\<name>\...); UNC paths carry server and share names.
        // Folder names may contain spaces ("My Photos\"); the last component ends at the first space.
        "WINPATH" to "(?:\\b[A-Za-z]:|\\\\\\\\[^\\s\\\\]+)\\\\(?:[^\\s\"'<>|\\\\]+(?: [^\\s\"'<>|\\\\]+)*\\\\)*[^\\s\"'<>|]*",
        "FILEPATH" to "(?:/[\\w.-]+){2,}",
        "SECURITYARTIFACT" to "security/[^\\s\"'}]+",
        "METADATAARTIFACT" to "metadata/[^\\s\"'}]+",
        // >= 40 base64 chars (a 32-byte key is 44) that contain a digit or +/, so long camelCase words survive.
        "BASE64" to "(?=[A-Za-z0-9+/]*[0-9+/])(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
        "BASE64URL" to "(?=[A-Za-z0-9_-]*[0-9_-])(?:[A-Za-z0-9_-]{4}){10,}(?:[A-Za-z0-9_-]{2,3})?",
        "HASHPATH" to "[a-fA-F0-9]{16}",
        "IPV4" to "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b",
        // MEGA handles: random base64url tokens of exactly 8 (node) or 11 (user) characters, containing a digit.
        // Readable identifiers of the same length are kept: tokens made only of single-class pieces (all lowercase,
        // all uppercase or all digits) joined by '-' or '_', such as "line-5-123" or "INFO-2024", which a random
        // handle almost never forms.
        "MEGAHANDLE" to "(?<![A-Za-z0-9_-])(?=(?:[A-Za-z0-9_-]{8}|[A-Za-z0-9_-]{11})(?![A-Za-z0-9_-]))(?=[A-Za-z0-9_-]*[0-9])" +
            "(?!(?:[a-z]+|[A-Z]+|[0-9]+)(?:[_-](?:[a-z]+|[A-Z]+|[0-9]+))*(?![A-Za-z0-9_-]))[A-Za-z0-9_-]{8,11}",
        // Media/document file names. Not followed by ".word", so package names like com.enc.sino stay readable.
        "FILENAME" to "\\b[\\w-]+\\.(?i:jpe?g|png|webp|heic|heif|gif|bmp|tiff?|dng|raw|mp4|mkv|mov|avi|webm|3gp|mp3|m4a|wav|" +
            "aac|flac|pdf|txt|docx?|xlsx?|pptx?|zip|7z|tmp|enc|batch|meta|sino|json|bin|public)(?!\\.?\\w)",
    )

    // Clean display name for presentation in logs
    private val displayLabels = mapOf(
        "CREDENTIAL" to "CREDENTIAL",
        "URL" to "URL",
        "JWT" to "JWT",
        "BEARER" to "AUTH_TOKEN",
        "PEM" to "PEM_KEY",
        "EMAIL" to "EMAIL",
        "BIP39" to "BIP39",
        "AUTHTOKEN" to "AUTH_TOKEN",
        "S3ACCESSKEY" to "S3_ACCESS_KEY",
        "S3SECRETKEY" to "S3_SECRET_KEY",
        "S3KEY" to "S3_KEY",
        "MEGACHALLENGE" to "MEGA_CHALLENGE",
        "MEGASESSION" to "MEGA_SESSION",
        "SENSITIVEID" to "SENSITIVE_ID",
        "WINPATH" to "FILE_PATH",
        "HASHPATH" to "HASH_PATH",
        "IPV4" to "IP",
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
     * Masks identifiers, secrets and platform-specific paths in one pass.
     *
     * @param input The raw log message.
     * @param platformPaths Literal paths to mask first (e.g. "/data/user/0/..." -> "[INTERNAL_STORAGE]").
     * @return The sanitized log message.
     */
    fun sanitize(input: String, platformPaths: Map<String, String> = emptyMap()): String {
        if (input.isEmpty()) return ""

        // 1. Mask platform-specific paths first (literal replacements), longest first so nested paths mask fully.
        var result = input
        platformPaths.entries.sortedByDescending { it.key.length }.forEach { (path, label) ->
            if (path.isNotEmpty()) result = result.replace(path, label)
        }

        // 2. Single-pass master redaction.
        val sanitized = masterRegex.replace(result) { matchResult ->
            val matchedLabel = labels.firstOrNull { label -> matchResult.groups[label] != null }
            if (matchedLabel != null) {
                "[REDACTED_${displayLabels[matchedLabel] ?: matchedLabel}]"
            } else {
                matchResult.value
            }
        }

        return sanitized
    }

    companion object {
        const val UNLOGGABLE = "[UNLOGGABLE MESSAGE]"
    }
}

/** [SinoPrivacyEngine.sanitize] for loggers: never throws, and never falls back to the raw text. */
fun SinoPrivacyEngine.sanitizeForLog(input: String, platformPaths: Map<String, String> = emptyMap()): String =
    try {
        sanitize(input, platformPaths)
    } catch (_: Exception) {
        SinoPrivacyEngine.UNLOGGABLE
    }
