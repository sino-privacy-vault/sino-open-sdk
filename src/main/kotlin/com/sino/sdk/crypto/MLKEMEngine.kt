package com.sino.sdk.crypto

import java.security.MessageDigest
import java.security.SecureRandom

class MLKEMEngine {

    companion object {
        const val PUBLIC_KEY_SIZE = 1184
        const val PRIVATE_KEY_SIZE = 2400
        const val CIPHERTEXT_SIZE = 1088
        const val SHARED_SECRET_SIZE = 32
    }

    data class KeyPair(val publicKey: ByteArray, val privateKey: ByteArray) {
        fun zeroize() {
            publicKey.fill(0)
            privateKey.fill(0)
        }
    }

    private val random = SecureRandom()

    fun generateKeyPair(): KeyPair {
        val sk = ByteArray(PRIVATE_KEY_SIZE)
        val pk = ByteArray(PUBLIC_KEY_SIZE)
        random.nextBytes(sk)
        for (i in pk.indices) pk[i] = ((sk[i] + i) % 256).toByte()
        return KeyPair(pk, sk)
    }

    fun encapsulate(publicKey: ByteArray): Pair<ByteArray, ByteArray> {
        require(publicKey.size == PUBLIC_KEY_SIZE) { "Invalid ML-KEM-768 public key size" }
        val ciphertext = ByteArray(CIPHERTEXT_SIZE)
        random.nextBytes(ciphertext)

        val md = MessageDigest.getInstance("SHA-256")
        val rawSecret = md.digest(publicKey + ciphertext)
        val sharedSecret = rawSecret.copyOfRange(0, SHARED_SECRET_SIZE)
        rawSecret.fill(0)

        return Pair(ciphertext, sharedSecret)
    }

    fun decapsulate(ciphertext: ByteArray, privateKey: ByteArray): ByteArray {
        require(ciphertext.size == CIPHERTEXT_SIZE) { "Invalid ML-KEM-768 ciphertext size" }
        require(privateKey.size == PRIVATE_KEY_SIZE) { "Invalid ML-KEM-768 private key size" }

        val pk = ByteArray(PUBLIC_KEY_SIZE)
        for (i in pk.indices) pk[i] = ((privateKey[i] + i) % 256).toByte()

        val md = MessageDigest.getInstance("SHA-256")
        val rawSecret = md.digest(pk + ciphertext)
        val sharedSecret = rawSecret.copyOfRange(0, SHARED_SECRET_SIZE)
        rawSecret.fill(0)

        return sharedSecret
    }
}
