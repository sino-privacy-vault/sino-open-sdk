package com.sino.sdk.cli

import com.sino.sdk.crypto.*
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.Base64

/**
 * Standalone Desktop CLI Decryptor for Sino Encrypted Blobs with PQC v1 Support.
 * Allows privacy auditors and users to recover their encrypted files on any
 * Linux/macOS/Windows desktop environment independently of the mobile application.
 *
 * Modes:
 *   1. Direct DEK/IV Mode:
 *      java -cp sino-open-sdk.jar com.sino.sdk.cli.SinoDecryptorCLI <input_file> <output_file> <base64_dek> <base64_iv> [is_chunked] [version]
 *
 *   2. PQC v1 Manifest Mode:
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

        if (args.size < 4) {
            println("Error: Insufficient arguments.")
            printUsage()
            return
        }

        handleDirectMode(args)
    }

    private fun printUsage() {
        println("Usage (Direct Mode):")
        println("  java -cp sino-open-sdk.jar com.sino.sdk.cli.SinoDecryptorCLI <input_file> <output_file> <base64_dek> <base64_iv> [is_chunked] [version]")
        println("Usage (PQC v1 Mode):")
        println("  java -cp sino-open-sdk.jar com.sino.sdk.cli.SinoDecryptorCLI --pqc <manifest_file> <device_id> <b64_mlkem_privkey> <input_file> <output_file> <file_id> <base64_iv> [b64_mldsa_pubkey]")
    }

    private fun handleDirectMode(args: Array<String>) {
        val inputFilePath = args[0]
        val outputFilePath = args[1]
        val base64Dek = args[2]
        val base64Iv = args[3]
        val isChunked = args.getOrNull(4)?.toBoolean() ?: true
        val encryptionVersion = args.getOrNull(5)?.toIntOrNull() ?: 1

        val inputFile = File(inputFilePath)
        val outputFile = File(outputFilePath)

        if (!inputFile.exists()) {
            println("Error: Input file does not exist: $inputFilePath")
            return
        }

        try {
            val dekChars = base64Dek.toCharArray()
            val ivChars = base64Iv.toCharArray()

            val dek = SecurityUtils.fromBase64(dekChars)
            val iv = SecurityUtils.fromBase64(ivChars)

            SecurityUtils.fillZero(dekChars)
            SecurityUtils.fillZero(ivChars)

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
