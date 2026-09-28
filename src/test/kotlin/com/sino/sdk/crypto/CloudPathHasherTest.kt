package com.sino.sdk.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CloudPathHasherTest {

    @Test
    fun `computeCloudFolderHash should produce deterministic 32-char hex string`() {
        val salt = "SinoTestSalt1234567890".toByteArray()
        val path1 = "DCIM/Camera/vacation.jpg"
        val path2 = "DCIM/Camera/vacation.jpg"

        val hash1 = CloudPathHasher.computeCloudFolderHash(path1, salt)
        val hash2 = CloudPathHasher.computeCloudFolderHash(path2, salt)

        assertEquals(hash1, hash2)
        assertEquals(32, hash1.length)
    }

    @Test
    fun `computeCloudFileHash should produce deterministic 32-char hex string`() {
        val salt = "SinoTestSalt1234567890".toByteArray()
        val checksum = "sha256-hash-of-file-content"

        val hash1 = CloudPathHasher.computeCloudFileHash(checksum, salt)
        val hash2 = CloudPathHasher.computeCloudFileHash(checksum, salt)

        assertEquals(hash1, hash2)
        assertEquals(32, hash1.length)
    }

    @Test
    fun `computeMetadataBatchHash should produce deterministic 32-char hex string with suffix`() {
        val salt = "SinoTestSalt1234567890".toByteArray()
        val folderId = 12345L

        val hash = CloudPathHasher.computeMetadataBatchHash(folderId, salt)
        
        assertTrue(hash.endsWith(".batch"))
        // 32 (hex) + 6 (.batch) = 38
        assertEquals(38, hash.length)
    }

    @Test
    fun `different inputs should produce different hashes`() {
        val salt = "SinoTestSalt1234567890".toByteArray()
        val path1 = "DCIM/Camera/vacation.jpg"
        val path2 = "DCIM/Camera/taxes.pdf"

        val hash1 = CloudPathHasher.computeCloudFolderHash(path1, salt)
        val hash2 = CloudPathHasher.computeCloudFolderHash(path2, salt)

        assertNotEquals(hash1, hash2)
    }
}
