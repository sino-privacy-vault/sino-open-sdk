package com.sino.sdk.cli

import com.sino.sdk.crypto.SecurityUtils
import com.sino.sdk.vault.RecoveryKit
import com.sino.sdk.vault.VaultRecovery
import java.io.File
import java.io.InputStream
import java.io.PrintStream
import java.text.SimpleDateFormat
import java.util.Date
import kotlin.system.exitProcess

/**
 * Standalone recovery of a Sino vault, independent of the Sino apps. It needs only the recovery phrase and a copy of
 * the `SinoVault` folder from one or more cloud providers; it makes no network connections.
 *
 * ```
 * recover          --vault <dir> [--vault <dir> ...] --out <dir> [--include-trashed] [phrase option]
 * list             --vault <dir> [--vault <dir> ...] [phrase option]
 * verify-manifest  --vault <dir> [--vault <dir> ...] [phrase option]
 *
 * phrase option:   --phrase-file <file> | --phrase-stdin   (default: a masked prompt)
 * ```
 * The phrase is never accepted as a command-line argument (it would show in process listings and shell history).
 */
object SinoDecryptorCLI {

    const val EXIT_OK = 0
    const val EXIT_PARTIAL = 1
    const val EXIT_ERROR = 2

    @JvmStatic
    fun main(args: Array<String>) {
        exitProcess(run(args, System.out, System.`in`))
    }

    fun run(args: Array<String>, out: PrintStream, stdin: InputStream): Int {
        val command = args.firstOrNull()
        if (command == null || command == "--help" || command == "-h") {
            printUsage(out)
            return if (command == null) EXIT_ERROR else EXIT_OK
        }
        val options = try {
            Options.parse(args.drop(1))
        } catch (e: IllegalArgumentException) {
            out.println("Error: ${e.message}")
            printUsage(out)
            return EXIT_ERROR
        }
        if (command !in setOf("recover", "list", "verify-manifest")) {
            out.println("Error: unknown command '$command'")
            printUsage(out)
            return EXIT_ERROR
        }
        if (options.vaults.isEmpty()) {
            out.println("Error: give at least one --vault folder (a downloaded SinoVault folder)")
            return EXIT_ERROR
        }
        options.vaults.firstOrNull { !it.isDirectory }?.let {
            out.println("Error: not a folder: ${it.path}")
            return EXIT_ERROR
        }
        if (command == "recover" && options.out == null) {
            out.println("Error: recover needs --out <folder>")
            return EXIT_ERROR
        }

        val phrase = try {
            readPhrase(options, stdin, out)
        } catch (e: IllegalArgumentException) {
            out.println("Error: ${e.message}")
            return EXIT_ERROR
        }
        val vault = try {
            out.println("Opening the recovery backup (this takes a few seconds)...")
            VaultRecovery.open(options.vaults, phrase)
        } catch (e: IllegalArgumentException) {
            out.println("Error: ${e.message}")
            return EXIT_ERROR
        } catch (e: IllegalStateException) {
            out.println("Error: ${e.message}")
            return EXIT_ERROR
        } finally {
            phrase.forEach { SecurityUtils.fillZero(it) }
        }

        return vault.use {
            when (command) {
                "recover" -> recover(it, options, out)
                "list" -> list(it, out)
                else -> verifyManifest(it, out)
            }
        }
    }

    private fun recover(vault: VaultRecovery, options: Options, out: PrintStream): Int {
        val outputDir = options.out!!
        val report = vault.recover(outputDir, options.includeTrashed) { out.println("  decrypting $it") }
        report.skipped.forEach { out.println("SKIPPED $it") }
        report.failed.forEach { out.println("FAILED  $it") }
        out.println("Recovered ${report.recovered.size} file(s) into ${outputDir.path}; ${report.failed.size} failed, ${report.skipped.size} skipped.")
        return if (report.failed.isEmpty()) EXIT_OK else EXIT_PARTIAL
    }

    private fun list(vault: VaultRecovery, out: PrintStream): Int {
        val index = vault.index()
        index.problems.forEach { out.println("WARNING $it") }
        index.files.forEach { file ->
            val flags = buildList {
                if (file.entry.isTrashed) add("trashed")
                if (file.copies.isEmpty()) add("NO COPY") else add("${file.copies.size} cop${if (file.copies.size == 1) "y" else "ies"}")
            }
            out.println("${file.path}  (${file.entry.size} bytes, ${flags.joinToString(", ")})")
        }
        out.println("${index.files.size} file(s).")
        return if (index.files.any { it.copies.isEmpty() }) EXIT_PARTIAL else EXIT_OK
    }

    private fun verifyManifest(vault: VaultRecovery, out: PrintStream): Int {
        val report = vault.verifyManifest()
        report.rejected.forEach { out.println("REJECTED $it") }
        val manifest = report.manifest ?: run {
            out.println("No device list signed by this vault was found.")
            return EXIT_PARTIAL
        }
        val date = SimpleDateFormat("yyyy-MM-dd HH:mm")
        out.println("Device list verified (ML-DSA-65): vault ${manifest.vaultIdentifier}, key epoch ${manifest.keyEpoch}, suite ${manifest.cryptoSuite}")
        manifest.keyEnvelopes.forEach { env ->
            out.println("  device ${env.keyId}  ${env.deviceName ?: "(unnamed)"} ${env.deviceType ?: ""}  enrolled ${date.format(Date(env.createdAt))}")
        }
        manifest.revokedKeyIds.forEach { out.println("  revoked ${it}") }
        return EXIT_OK
    }

    /** The phrase as words (char arrays the caller wipes); never a String. */
    private fun readPhrase(options: Options, stdin: InputStream, out: PrintStream): List<CharArray> {
        val chars: CharArray = when {
            options.phraseFile != null -> {
                val file = options.phraseFile
                require(file.isFile) { "phrase file not found: ${file.path}" }
                val bytes = file.readBytes()
                try { SecurityUtils.fromUtf8(bytes) } finally { SecurityUtils.fillZero(bytes) }
            }
            options.phraseStdin -> {
                val bytes = stdin.readBytes()
                try { SecurityUtils.fromUtf8(bytes) } finally { SecurityUtils.fillZero(bytes) }
            }
            else -> {
                val console = System.console()
                    ?: throw IllegalArgumentException("no console for a masked prompt; use --phrase-file or --phrase-stdin")
                out.flush()
                console.readPassword("Recovery phrase (24 words, input hidden): ")
                    ?: throw IllegalArgumentException("no recovery phrase entered")
            }
        }
        return try {
            RecoveryKit.splitWords(chars).also {
                if (it.size != RecoveryKit.PHRASE_WORDS) {
                    it.forEach { word -> SecurityUtils.fillZero(word) }
                    throw IllegalArgumentException("a recovery phrase has ${RecoveryKit.PHRASE_WORDS} words (got ${it.size})")
                }
            }
        } finally {
            SecurityUtils.fillZero(chars)
        }
    }

    private class Options(
        val vaults: List<File>,
        val out: File?,
        val phraseFile: File?,
        val phraseStdin: Boolean,
        val includeTrashed: Boolean,
    ) {
        companion object {
            fun parse(args: List<String>): Options {
                val vaults = mutableListOf<File>()
                var out: File? = null
                var phraseFile: File? = null
                var phraseStdin = false
                var includeTrashed = false
                var i = 0
                fun value(flag: String): String = args.getOrNull(++i) ?: throw IllegalArgumentException("$flag needs a value")
                while (i < args.size) {
                    when (val flag = args[i]) {
                        "--vault" -> vaults += File(value(flag))
                        "--out" -> out = File(value(flag))
                        "--phrase-file" -> phraseFile = File(value(flag))
                        "--phrase-stdin" -> phraseStdin = true
                        "--include-trashed" -> includeTrashed = true
                        else -> throw IllegalArgumentException("unknown option '$flag'")
                    }
                    i++
                }
                require(!(phraseFile != null && phraseStdin)) { "use either --phrase-file or --phrase-stdin, not both" }
                return Options(vaults, out, phraseFile, phraseStdin, includeTrashed)
            }
        }
    }

    private fun printUsage(out: PrintStream) {
        out.println(
            """
            Sino vault recovery (offline). Download the SinoVault folder from each cloud provider you used, then:

              recover          --vault <dir> [--vault <dir> ...] --out <dir> [--include-trashed] [phrase option]
              list             --vault <dir> [--vault <dir> ...] [phrase option]
              verify-manifest  --vault <dir> [--vault <dir> ...] [phrase option]

            Phrase option: --phrase-file <file> | --phrase-stdin   (default: a masked prompt)
            Existing files in the output folder are never overwritten.
            """.trimIndent()
        )
    }
}
