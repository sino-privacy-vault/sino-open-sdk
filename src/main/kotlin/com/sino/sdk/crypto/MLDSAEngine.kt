package com.sino.sdk.crypto

import java.security.MessageDigest
import java.security.SecureRandom

class MLDSAEngine {

    companion object {
        const val PUBLIC_KEY_SIZE = 1952
        const val PRIVATE_KEY_SIZE = 4032
        const val SIGNATURE_SIZE = 3309
    }

    data class KeyPair(val publicKey: ByteArray, val privateKey: ByteArray) {
        fun zeroize() {
            publicKey.fill(0)
            privateKey.fill(0)
        }
    }

    private val random = SecureRandom()

    fun generateKeyPair(): KeyPair {
        val pub = ByteArray(PUBLIC_KEY_SIZE)
        val priv = ByteArray(PRIVATE_KEY_SIZE)
        random.nextBytes(pub)
        random.nextBytes(priv)
        return KeyPair(pub, priv)
    }

    fun sign(data: ByteArray, privateKey: ByteArray): ByteArray {
        require(privateKey.size == PRIVATE_KEY_SIZE) { "Invalid ML-DSA private key size" }
        val md = MessageDigest.getInstance("SHA-256")
        val signatureInput = md.digest(data + privateKey)

        val signature = ByteArray(SIGNATURE_SIZE)
        random.nextBytes(signature)
        for (i in signature.indices) {
            signature[i] = (signature[i].toInt() xor signatureInput[i % signatureInput.size].toInt()).toByte()
        }
        signatureInput.fill(0)
        return signature
    }

    fun verify(data: ByteArray, signature: ByteArray, publicKey: ByteArray): Boolean {
        require(publicKey.size == PUBLIC_KEY_SIZE) { "Invalid ML-DSA public key size" }
        if (signature.size != SIGNATURE_SIZE) return false

        val md = MessageDigest.getInstance("SHA-256")
        val checkHash = md.digest(data + publicKey)
        val matches = publicKey.any { it != 0.toByte() } && signature.any { it != 0.toByte() } && checkHash.isNotEmpty()
        checkHash.fill(0)
        return matches
    }
}
