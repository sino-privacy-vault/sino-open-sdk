package com.sino.sdk.cli

import com.sino.sdk.crypto.*
import java.io.BufferedReader
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStreamReader
import java.util.Base64
import java.util.Scanner

/**
 * Standalone Desktop CLI Decryptor for Sino Encrypted Blobs with PQC v1 Support.
 * Allows privacy auditors and users to recover their encrypted files on any
 * Linux/macOS/Windows desktop environment independently of the mobile application.
 *
 * Secure Key Modes:
 *   1. Secure Key File Mode (Recommended):
 *      java -cp sino-open-sdk.jar com.sino.sdk.cli.SinoDecryptorCLI <input_file> <output_file> --key-file <key_file_path> [is_chunked] [version]
 *
 *   2. Secure Stdin Pipe Mode:
 *      java -cp sino-open-sdk.jar com.sino.sdk.cli.SinoDecryptorCLI <input_file> <output_file> --key-stdin [is_chunked] [version]
 *
 *   3. Interactive Masked Prompt Mode:
 *      java -cp sino-open-sdk.jar com.sino.sdk.cli.SinoDecryptorCLI <input_file> <output_file> [is_chunked] [version]
 *
 *   4. Direct Arguments (Deprecated / Security Warning):
 *      java -cp sino-open-sdk.jar com.sino.sdk.cli.SinoDecryptorCLI <input_file> <output_file> <base64_dek> <base64_iv> [is_chunked] [version]
 *
 *   5. PQC v1 Manifest Mode:
 *      java -cp sino-open-sdk.jar com.sino.sdk.cli.SinoDecryptorCLI --pqc <manifest_file> <device_id> <b64_mlkem_privkey> <input_file> <output_file> <file_id> <base64_iv> [b64_mldsa_pubkey]
 */
object SinoDecryptorCLI {

    @JvmStatic
    fun main(args: Array<String>) {
        println("=== Sino Open Security SDK - Decryptor CLI (PQC v1 Enabled) ===")

        if (args.isEmpty()) {
            printUsage()
            return
        }

        if (args[0] == "--pqc") {
            handlePqcMode(args.drop(1).toTypedArray())
            return
        }

        if (args.size < 2) {
            println("Error: Insufficient arguments. Minimum requires <input_file> <output_file>.")
            printUsage()
            return
        }

        handleDirectMode(args)
    }

    private fun printUsage() {
        println("Usage Options:")
        println("  1. Secure Key File (Recommended):")
        println("     java -cp sino-open-sdk.jar com.sino.sdk.cli.SinoDecryptorCLI <input_file> <output_file> --key-file <key_file_path> [is_chunked] [version]")
        println("  2. Secure Stdin Pipe:")
        println("     java -cp sino-open-sdk.jar com.sino.sdk.cli.SinoDecryptorCLI <input_file> <output_file> --key-stdin [is_chunked] [version]")
        println("  3. Interactive Masked Prompt:")
        println("     java -cp sino-open-sdk.jar com.sino.sdk.cli.SinoDecryptorCLI <input_file> <output_file> [is_chunked] [version]")
        println("  4. PQC v1 Manifest Mode:")
        println("     java -cp sino-open-sdk.jar com.sino.sdk.cli.SinoDecryptorCLI --pqc <manifest_file> <device_id> <b64_mlkem_privkey> <input_file> <output_file> <file_id> <base64_iv> [b64_mldsa_pubkey]")
    }

    private fun handleDirectMode(args: Array<String>) {
        val inputFilePath = args[0]
        val outputFilePath = args[1]

        val inputFile = File(inputFilePath)
        val outputFile = File(outputFilePath)

        if (!inputFile.exists()) {
            println("Error: Input file does not exist: $inputFilePath")
            return
        }

        var dekChars: CharArray? = null
        var ivChars: CharArray? = null
        var isChunked = true
        var encryptionVersion = 1

        val remainingArgs = args.drop(2)
        try {
            when {
                remainingArgs.contains("--key-file") || remainingArgs.contains("-k") -> {
                    val keyFileIdx = if (remainingArgs.indexOf("--key-file") != -1) remainingArgs.indexOf("--key-file") else remainingArgs.indexOf("-k")
                    val keyFilePath = remainingArgs.getOrNull(keyFileIdx + 1)
                        ?: run {
                            println("Error: Missing key file path after --key-file.")
                            return
                        }
                    val keyFile = File(keyFilePath)
                    if (!keyFile.exists()) {
                        println("Error: Key file does not exist: $keyFilePath")
                        return
                    }
                    val keys = readKeysFromFile(keyFile)
                    dekChars = keys.first
                    ivChars = keys.second
                    
                    val flags = remainingArgs.filterIndexed { index, _ -> index != keyFileIdx && index != keyFileIdx + 1 }
                    isChunked = flags.getOrNull(0)?.toBoolean() ?: true
                    encryptionVersion = flags.getOrNull(1)?.toIntOrNull() ?: 1
                }
                remainingArgs.contains("--key-stdin") -> {
                    println("Reading Base64 DEK and IV from stdin...")
                    val keys = readKeysFromStdin()
                    dekChars = keys.first
                    ivChars = keys.second

                    val flags = remainingArgs.filter { it != "--key-stdin" }
                    isChunked = flags.getOrNull(0)?.toBoolean() ?: true
                    encryptionVersion = flags.getOrNull(1)?.toIntOrNull() ?: 1
                }
                remainingArgs.size >= 2 && !remainingArgs[0].startsWith("-") -> {
                    println("[SECURITY WARNING] Passing secret keys as CLI positional arguments exposes them in process listings (ps) and shell history.")
                    println("                  Consider using --key-file, --key-stdin, or interactive prompt mode instead.")
                    dekChars = remainingArgs[0].toCharArray()
                    ivChars = remainingArgs[1].toCharArray()
                    isChunked = remainingArgs.getOrNull(2)?.toBoolean() ?: true
                    encryptionVersion = remainingArgs.getOrNull(3)?.toIntOrNull() ?: 1
                }
                else -> {
                    println("Prompting for secret key credentials interactively...")
                    val keys = readKeysInteractively()
                    dekChars = keys.first
                    ivChars = keys.second
                    isChunked = remainingArgs.getOrNull(0)?.toBoolean() ?: true
                    encryptionVersion = remainingArgs.getOrNull(1)?.toIntOrNull() ?: 1
                }
            }

            if (dekChars.isEmpty() || ivChars.isEmpty()) {
                println("Error: DEK or IV credentials could not be read.")
                return
            }

            val dek = SecurityUtils.fromBase64(dekChars)
            val iv = SecurityUtils.fromBase64(ivChars)

            val engine = AESEncryptionEngine()

            println("Decrypting [${inputFile.name}] -> [${outputFile.name}] (Chunked: $isChunked, Version: $encryptionVersion)...")
            FileInputStream(inputFile).use { inStream ->
                FileOutputStream(outputFile).use { outStream ->
                    if (isChunked) {
                        engine.decryptChunked(inStream, outStream, dek, iv, 1024 * 1024, encryptionVersion)
                    } else {
                        engine.decrypt(inStream, outStream, dek, iv)
                    }
                }
            }

            SecurityUtils.fillZero(dek)
            SecurityUtils.fillZero(iv)

            println("SUCCESS: File decrypted cleanly (${outputFile.length()} bytes). Integrity verified.")
            SecurityUtils.requestSystemGc()
        } catch (e: Exception) {
            println("DECRYPTION FAILED: ${e.message}")
            e.printStackTrace()
        } finally {
            dekChars?.let { SecurityUtils.fillZero(it) }
            ivChars?.let { SecurityUtils.fillZero(it) }
        }
    }

    private fun readKeysFromFile(keyFile: File): Pair<CharArray, CharArray> {
        val lines = keyFile.readLines().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }
        var dek: String? = null
        var iv: String? = null

        for (line in lines) {
            when {
                line.startsWith("DEK=") || line.startsWith("dek=") -> dek = line.substringAfter("=").trim()
                line.startsWith("IV=") || line.startsWith("iv=") -> iv = line.substringAfter("=").trim()
            }
        }

        if (dek == null && lines.isNotEmpty()) dek = lines[0]
        if (iv == null && lines.size > 1) iv = lines[1]

        return Pair(
            dek?.toCharArray() ?: CharArray(0),
            iv?.toCharArray() ?: CharArray(0)
        )
    }

    private fun readKeysFromStdin(): Pair<CharArray, CharArray> {
        val reader = BufferedReader(InputStreamReader(System.`in`))
        val dekLine = reader.readLine()?.trim() ?: ""
        val ivLine = reader.readLine()?.trim() ?: ""
        return Pair(
            dekLine.substringAfter("DEK=").trim().toCharArray(),
            ivLine.substringAfter("IV=").trim().toCharArray()
        )
    }

    private fun readKeysInteractively(): Pair<CharArray, CharArray> {
        val console = System.console()
        return if (console != null) {
            val dekChars = console.readPassword("Enter Base64 DEK: ")
            val ivChars = console.readPassword("Enter Base64 IV: ")
            Pair(dekChars, ivChars)
        } else {
            val scanner = Scanner(System.`in`)
            print("Enter Base64 DEK: ")
            val dek = scanner.nextLine().trim()
            print("Enter Base64 IV: ")
            val iv = scanner.nextLine().trim()
            Pair(dek.toCharArray(), iv.toCharArray())
        }
    }

    private fun handlePqcMode(args: Array<String>) {
        if (args.size < 7) {
            println("Error: Insufficient PQC arguments.")
            printUsage()
            return
        }

        val manifestPath = args[0]
        val deviceId = args[1]
        val b64MlKemPrivKey = args[2]
        val inputFilePath = args[3]
        val outputFilePath = args[4]
        val fileId = args[5].toLongOrNull() ?: 0L
        val base64Iv = args[6]
        val b64MlDsaPubKey = args.getOrNull(7)

        val manifestFile = File(manifestPath)
        val inputFile = File(inputFilePath)
        val outputFile = File(outputFilePath)

        if (!manifestFile.exists() || !inputFile.exists()) {
            println("Error: Manifest or input file missing.")
            return
        }

        try {
            val manifestJson = manifestFile.readText()
            val manifest = VaultManifest.fromJson(manifestJson)

            // 1. Verify Manifest ML-DSA Signature if public key supplied
            if (b64MlDsaPubKey != null && manifest.mldsaSignatureBase64 != null) {
                val mlDsa = MLDSAEngine()
                val pubKey = Base64.getDecoder().decode(b64MlDsaPubKey)
                val signature = Base64.getDecoder().decode(manifest.mldsaSignatureBase64)

                val unsignedManifest = manifest.copy(mldsaSignatureBase64 = null)
                val payload = unsignedManifest.toJson().encodeToByteArray()

                val isValid = mlDsa.verify(payload, signature, pubKey)
                if (!isValid) {
                    println("CRITICAL: Vault Manifest ML-DSA-65 signature verification failed!")
                    return
                }
                println("PQC Guard: Vault Manifest ML-DSA-65 signature verified.")
            }

            // 2. Unwrap ML-KEM-768 Device Key Envelope
            val envelope = manifest.keyEnvelopes.find { it.keyId == deviceId }
                ?: run {
                    println("Error: Device [$deviceId] not found in vault key envelopes. Access revoked.")
                    return
                }

            val mlKemPrivKey = Base64.getDecoder().decode(b64MlKemPrivKey)
            val deviceManager = DeviceKeyManager()
            val vaultKey = deviceManager.unwrapDeviceEnvelope(envelope, mlKemPrivKey)

            // 3. Derive File DEK via HKDF-SHA-512
            val hkdfEngine = HKDFEngine()
            val dek = hkdfEngine.deriveFileKey(vaultKey, fileId)

            val iv = Base64.getDecoder().decode(base64Iv)
            val engine = AESEncryptionEngine()

            println("PQC Decrypting [${inputFile.name}] -> [${outputFile.name}] (File ID: $fileId)...")
            FileInputStream(inputFile).use { inStream ->
                FileOutputStream(outputFile).use { outStream ->
                    engine.decryptChunked(inStream, outStream, dek, iv, 1024 * 1024, 1)
                }
            }

            SecurityUtils.fillZero(vaultKey)
            SecurityUtils.fillZero(dek)
            SecurityUtils.fillZero(iv)
            SecurityUtils.fillZero(mlKemPrivKey)

            println("PQC SUCCESS: File decrypted cleanly (${outputFile.length()} bytes). ML-KEM-768 envelope verified.")
            SecurityUtils.requestSystemGc()
        } catch (e: Exception) {
            println("PQC DECRYPTION FAILED: ${e.message}")
            e.printStackTrace()
        }
    }
}
