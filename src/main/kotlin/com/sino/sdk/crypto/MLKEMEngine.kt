package com.sino.sdk.crypto

import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator
import org.bouncycastle.crypto.kems.MLKEMExtractor
import org.bouncycastle.crypto.kems.MLKEMGenerator
import org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters
import org.bouncycastle.crypto.params.MLKEMParameters
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters
import java.security.SecureRandom

/**
 * ML-KEM-768 (NIST FIPS 203), backed by BouncyCastle: an implementation independent of Sino's own, so the SDK also
 * cross-checks it. Keys use the FIPS 203 encodings (public 1,184 bytes, expanded private 2,400 bytes); a 64-byte
 * private key is a `d || z` seed, the form Sino keeps for each device.
 */
class MLKEMEngine(private val random: SecureRandom = SecureRandom()) {

    companion object {
        const val PUBLIC_KEY_SIZE = 1184
        const val PRIVATE_KEY_SIZE = 2400
        const val SEED_SIZE = 64
        const val CIPHERTEXT_SIZE = 1088
        const val SHARED_SECRET_SIZE = 32
        private val PARAMS = MLKEMParameters.ml_kem_768
    }

    class KeyPair(val publicKey: ByteArray, val privateKey: ByteArray) {
        fun zeroize() {
            publicKey.fill(0)
            privateKey.fill(0)
        }
    }

    fun generateKeyPair(): KeyPair {
        val pair = MLKEMKeyPairGenerator().apply { init(MLKEMKeyGenerationParameters(random, PARAMS)) }.generateKeyPair()
        val private = (pair.private as MLKEMPrivateKeyParameters).getParametersWithFormat(MLKEMPrivateKeyParameters.EXPANDED_KEY)
        return KeyPair((pair.public as MLKEMPublicKeyParameters).encoded, private.encoded)
    }

    /** The key pair of a 64-byte `d || z` seed (FIPS 203 ML-KEM.KeyGen_internal). */
    fun keyPairFromSeed(seed: ByteArray): KeyPair {
        require(seed.size == SEED_SIZE) { "ML-KEM-768 seed must be $SEED_SIZE bytes" }
        val private = MLKEMPrivateKeyParameters(PARAMS, seed)
        return KeyPair(private.publicKeyParameters.encoded, private.getParametersWithFormat(MLKEMPrivateKeyParameters.EXPANDED_KEY).encoded)
    }

    /** Returns Pair(ciphertext, sharedSecret). */
    fun encapsulate(publicKey: ByteArray): Pair<ByteArray, ByteArray> {
        require(publicKey.size == PUBLIC_KEY_SIZE) { "Invalid ML-KEM-768 public key size" }
        val encapsulated = MLKEMGenerator(random).generateEncapsulated(MLKEMPublicKeyParameters(PARAMS, publicKey))
        return Pair(encapsulated.encapsulation, encapsulated.secret)
    }

    /** [privateKey] is the 2,400-byte expanded key or the 64-byte seed. */
    fun decapsulate(ciphertext: ByteArray, privateKey: ByteArray): ByteArray {
        require(ciphertext.size == CIPHERTEXT_SIZE) { "Invalid ML-KEM-768 ciphertext size" }
        require(privateKey.size == PRIVATE_KEY_SIZE || privateKey.size == SEED_SIZE) { "Invalid ML-KEM-768 private key size" }
        return MLKEMExtractor(MLKEMPrivateKeyParameters(PARAMS, privateKey)).extractSecret(ciphertext)
    }
}
