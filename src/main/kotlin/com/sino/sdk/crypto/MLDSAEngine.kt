package com.sino.sdk.crypto

import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters
import org.bouncycastle.crypto.params.MLDSAParameters
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters
import org.bouncycastle.crypto.params.ParametersWithRandom
import org.bouncycastle.crypto.signers.MLDSASigner
import java.security.SecureRandom

/**
 * ML-DSA-65 (NIST FIPS 204, pure mode, empty context), backed by BouncyCastle: an implementation independent of
 * Sino's own. Keys use the FIPS 204 encodings (public 1,952 bytes, expanded private 4,032 bytes); a 32-byte private
 * key is the seed ξ, which is how Sino derives the vault's manifest signer from the vault root.
 */
class MLDSAEngine(private val random: SecureRandom = SecureRandom()) {

    companion object {
        const val PUBLIC_KEY_SIZE = 1952
        const val PRIVATE_KEY_SIZE = 4032
        const val SEED_SIZE = 32
        const val SIGNATURE_SIZE = 3309
        private val PARAMS = MLDSAParameters.ml_dsa_65
    }

    class KeyPair(val publicKey: ByteArray, val privateKey: ByteArray) {
        fun zeroize() {
            publicKey.fill(0)
            privateKey.fill(0)
        }
    }

    fun generateKeyPair(): KeyPair {
        val pair = MLDSAKeyPairGenerator().apply { init(MLDSAKeyGenerationParameters(random, PARAMS)) }.generateKeyPair()
        val private = (pair.private as MLDSAPrivateKeyParameters).getParametersWithFormat(MLDSAPrivateKeyParameters.EXPANDED_KEY)
        return KeyPair((pair.public as MLDSAPublicKeyParameters).encoded, private.encoded)
    }

    /** The key pair of a 32-byte seed ξ (FIPS 204 ML-DSA.KeyGen_internal). */
    fun keyPairFromSeed(xi: ByteArray): KeyPair {
        require(xi.size == SEED_SIZE) { "ML-DSA-65 seed must be $SEED_SIZE bytes" }
        val private = MLDSAPrivateKeyParameters(PARAMS, xi)
        return KeyPair(private.publicKeyParameters.encoded, private.getParametersWithFormat(MLDSAPrivateKeyParameters.EXPANDED_KEY).encoded)
    }

    /** Hedged signature; [privateKey] is the 4,032-byte expanded key or the 32-byte seed. */
    fun sign(data: ByteArray, privateKey: ByteArray): ByteArray {
        require(privateKey.size == PRIVATE_KEY_SIZE || privateKey.size == SEED_SIZE) { "Invalid ML-DSA-65 private key size" }
        val signer = MLDSASigner()
        signer.init(true, ParametersWithRandom(MLDSAPrivateKeyParameters(PARAMS, privateKey), random))
        signer.update(data, 0, data.size)
        return signer.generateSignature()
    }

    /** False for any malformed key or signature, never an exception. */
    fun verify(data: ByteArray, signature: ByteArray, publicKey: ByteArray): Boolean {
        if (publicKey.size != PUBLIC_KEY_SIZE || signature.size != SIGNATURE_SIZE) return false
        return try {
            val verifier = MLDSASigner()
            verifier.init(false, MLDSAPublicKeyParameters(PARAMS, publicKey))
            verifier.update(data, 0, data.size)
            verifier.verifySignature(signature)
        } catch (e: Exception) {
            false
        }
    }
}
