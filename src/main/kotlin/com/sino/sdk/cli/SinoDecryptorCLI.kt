package com.sino.sdk.cli

import com.sino.sdk.crypto.SecurityUtils
import com.sino.sdk.org.OrganisationRecovery
import com.sino.sdk.share.SharedFolderRecovery
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
 * the `SinoVault` folder from one or more cloud providers; it makes no network connections. A managed vault opens
 * instead with its recovery file and a quorum of the organisation's kits (SPECIFICATION.md §12).
 *
 * ```
 * recover          --vault <dir> [--vault <dir> ...] --out <dir> [--include-trashed] [key option]
 * list             --vault <dir> [--vault <dir> ...] [key option]
 * verify-manifest  --vault <dir> [--vault <dir> ...] [key option]
 * share-list       --share <dir> --kit <file> [--kit <file> ...] [--kit-passphrases <file>]
 * share-recover    --share <dir> --out <dir> [--include-trashed] --kit <file> [--kit <file> ...] [--kit-passphrases <file>]
 *
 * key option:      --phrase-file <file> | --phrase-stdin   (default: a masked prompt)
 *              or  --recovery-file <file> --kit <file> [--kit <file> ...] [--kit-passphrases <file>] [--hsm-answer <base64>]
 * ```
 * When the organisation keeps its recovery key's RSA half in an HSM, a first run prints what the HSM must decrypt;
 * the run again takes its answer with `--hsm-answer` (32 bytes, base64: one recovery's secret, which opens nothing
 * without the kits).
 * A shared folder (SPECIFICATION.md §13) opens with the organisation's kits: `--share` is a copy of its storage,
 * `shares/<share id>/`.
 * The phrase and kit passphrases are never accepted as command-line arguments (they would show in process listings
 * and shell history).
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
        if (command == "share-list" || command == "share-recover") return share(command, options, out)
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

        val vault = if (options.recoveryFile != null) {
            try {
                openWithKits(options, out)
            } catch (e: IllegalArgumentException) {
                out.println("Error: ${e.message}")
                return EXIT_ERROR
            }
        } else {
            val phrase = try {
                readPhrase(options, stdin, out)
            } catch (e: IllegalArgumentException) {
                out.println("Error: ${e.message}")
                return EXIT_ERROR
            }
            try {
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
            val info = vault.deviceInfo(env)
            out.println("  device ${env.keyId}  ${info?.name ?: "(unnamed)"} ${info?.type ?: ""}  enrolled ${date.format(Date(env.createdAt))}")
        }
        manifest.revokedKeyIds.forEach { out.println("  revoked ${it}") }
        return EXIT_OK
    }

    /** A shared folder, opened with the organisation's kits: its files listed, or written to `--out`. */
    private fun share(command: String, options: Options, out: PrintStream): Int {
        val folder = options.share ?: run {
            out.println("Error: give the shared folder's storage with --share <dir> (a copy of shares/<share id>/)")
            return EXIT_ERROR
        }
        if (command == "share-recover" && options.out == null) {
            out.println("Error: share-recover needs --out <folder>")
            return EXIT_ERROR
        }
        return try {
            val manifest = SharedFolderRecovery.readManifest(folder)
            OrganisationRecovery.open(readKits(options, out)).use { orgKeys ->
                options.hsmAnswer?.let(orgKeys::answerHsm)
                SharedFolderRecovery.openWithKits(manifest, orgKeys).use { keys ->
                    val index = SharedFolderRecovery.index(folder, manifest, keys)
                    out.println("Shared folder \"${index.name}\": ${index.files.size} file(s), ${index.trash.size} in its trash.")
                    if (index.refusedBatches > 0) out.println("WARNING ${index.refusedBatches} member batch(es) did not check out and were left out")
                    if (command == "share-list") {
                        (index.files + index.trash).forEach { f ->
                            out.println("${f.path}  (${f.entry.size} bytes${if (f.entry.trashed) ", trashed" else ""}${if (f.conflict) ", conflict" else ""})")
                        }
                        EXIT_OK
                    } else {
                        val written = SharedFolderRecovery.recover(folder, index, keys, options.out!!, options.includeTrashed)
                        out.println("Recovered ${written.size} file(s) into ${options.out.path}.")
                        EXIT_OK
                    }
                }
            }
        } catch (e: IllegalArgumentException) {
            out.println("Error: ${e.message}")
            EXIT_ERROR
        } catch (e: Exception) {
            out.println("Error: ${e.message ?: e::class.simpleName}")
            EXIT_PARTIAL
        }
    }

    /**
     * A managed vault: the kits rebuild the organisation's recovery key, which opens the vault's recovery file. Sealed
     * kits take the next line of `--kit-passphrases`, else a masked prompt.
     */
    private fun openWithKits(options: Options, out: PrintStream): VaultRecovery {
        require(options.kits.isNotEmpty()) { "--recovery-file needs the organisation's kits (--kit <file>, as many as its threshold)" }
        val recoveryFile = options.recoveryFile!!
        require(recoveryFile.isFile) { "recovery file not found: ${recoveryFile.path}" }
        OrganisationRecovery.open(readKits(options, out)).use { keys ->
            options.hsmAnswer?.let(keys::answerHsm)
            OrganisationRecovery.openRecoveryFile(recoveryFile.readText(), keys).use { opened ->
                return VaultRecovery.openWithKeys(options.vaults, opened.rootKey, opened.vaultSalt)
            }
        }
    }

    /** The kits given with `--kit`. Sealed kits take the next line of `--kit-passphrases`, else a masked prompt. */
    private fun readKits(options: Options, out: PrintStream): List<OrganisationRecovery.OrgKit> {
        require(options.kits.isNotEmpty()) { "give the organisation's kits (--kit <file>, as many as its threshold)" }
        options.kits.firstOrNull { !it.isFile }?.let { throw IllegalArgumentException("kit not found: ${it.path}") }
        val passphrases = options.kitPassphrases?.let { file ->
            require(file.isFile) { "passphrase file not found: ${file.path}" }
            val bytes = file.readBytes()
            val chars = try { SecurityUtils.fromUtf8(bytes) } finally { SecurityUtils.fillZero(bytes) }
            try { splitLines(chars) } finally { SecurityUtils.fillZero(chars) }
        }.orEmpty().toMutableList()
        try {
            out.println("Opening the organisation's kits (sealed kits take a few seconds each)...")
            return options.kits.map { file ->
                val text = file.readText()
                try {
                    OrganisationRecovery.readKit(text)
                } catch (e: OrganisationRecovery.PassphraseNeededException) {
                    val passphrase = if (passphrases.isNotEmpty()) passphrases.removeAt(0) else {
                        val console = System.console()
                            ?: throw IllegalArgumentException("${e.holder}'s kit has a passphrase; give it with --kit-passphrases <file>")
                        console.readPassword("Passphrase for ${e.holder}'s kit (input hidden): ")
                            ?: throw IllegalArgumentException("no passphrase entered")
                    }
                    try {
                        OrganisationRecovery.readKit(text, passphrase)
                    } finally {
                        SecurityUtils.fillZero(passphrase)
                    }
                }
            }
        } finally {
            passphrases.forEach { SecurityUtils.fillZero(it) }
        }
    }

    /** Non-empty lines, as char arrays the caller wipes. */
    private fun splitLines(chars: CharArray): List<CharArray> {
        val lines = mutableListOf<CharArray>()
        var start = 0
        for (i in 0..chars.size) {
            if (i == chars.size || chars[i] == '\n' || chars[i] == '\r') {
                if (i > start) lines += chars.copyOfRange(start, i)
                start = i + 1
            }
        }
        return lines
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
        val recoveryFile: File? = null,
        val kits: List<File> = emptyList(),
        val kitPassphrases: File? = null,
        val share: File? = null,
        /** The organisation's HSM's answer, when its recovery key's RSA half is there. */
        val hsmAnswer: String? = null,
    ) {
        companion object {
            fun parse(args: List<String>): Options {
                val vaults = mutableListOf<File>()
                var out: File? = null
                var phraseFile: File? = null
                var phraseStdin = false
                var includeTrashed = false
                var recoveryFile: File? = null
                val kits = mutableListOf<File>()
                var kitPassphrases: File? = null
                var share: File? = null
                var hsmAnswer: String? = null
                var i = 0
                fun value(flag: String): String = args.getOrNull(++i) ?: throw IllegalArgumentException("$flag needs a value")
                while (i < args.size) {
                    when (val flag = args[i]) {
                        "--vault" -> vaults += File(value(flag))
                        "--out" -> out = File(value(flag))
                        "--phrase-file" -> phraseFile = File(value(flag))
                        "--phrase-stdin" -> phraseStdin = true
                        "--include-trashed" -> includeTrashed = true
                        "--recovery-file" -> recoveryFile = File(value(flag))
                        "--kit" -> kits += File(value(flag))
                        "--kit-passphrases" -> kitPassphrases = File(value(flag))
                        "--share" -> share = File(value(flag))
                        "--hsm-answer" -> hsmAnswer = value(flag)
                        else -> throw IllegalArgumentException("unknown option '$flag'")
                    }
                    i++
                }
                require(!(phraseFile != null && phraseStdin)) { "use either --phrase-file or --phrase-stdin, not both" }
                require(recoveryFile == null || (phraseFile == null && !phraseStdin)) { "use either the recovery phrase or the recovery file and kits, not both" }
                require(kits.isEmpty() || recoveryFile != null || share != null) { "--kit goes with --recovery-file or --share" }
                require(hsmAnswer == null || kits.isNotEmpty()) { "--hsm-answer goes with the kits" }
                return Options(vaults, out, phraseFile, phraseStdin, includeTrashed, recoveryFile, kits, kitPassphrases, share, hsmAnswer)
            }
        }
    }

    private fun printUsage(out: PrintStream) {
        out.println(
            """
            Sino vault recovery (offline). Download the SinoVault folder from each cloud provider you used, then:

              recover          --vault <dir> [--vault <dir> ...] --out <dir> [--include-trashed] [key option]
              list             --vault <dir> [--vault <dir> ...] [key option]
              verify-manifest  --vault <dir> [--vault <dir> ...] [key option]
              share-list       --share <dir> --kit <file> [--kit <file> ...] [--kit-passphrases <file>]
              share-recover    --share <dir> --out <dir> [--include-trashed] --kit <file> [--kit <file> ...]

            A shared folder of your organisation opens with its kits; --share is a copy of its storage
            (shares/<share id>/).

            Key option:  --phrase-file <file> | --phrase-stdin   (default: a masked prompt)
                    or, for a vault your organisation manages:
                         --recovery-file <file> --kit <file> [--kit <file> ...] [--kit-passphrases <file>]
                         (enough kits for the threshold; sealed kits take the next line of the passphrase file, or ask)
                         [--hsm-answer <base64>]  when your organisation keeps the recovery key's RSA half in an
                         HSM: the first run prints what it must decrypt; run again with its answer
            Existing files in the output folder are never overwritten.
            """.trimIndent()
        )
    }
}
