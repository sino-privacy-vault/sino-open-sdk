package com.sino.sdk.vault

import org.junit.Assert.assertEquals
import org.junit.Test

/** Merging the copies of a folder's batch when a file was edited: an edit is never undone by a later copy. */
class FolderMetadataBatchMergeTest {

    private fun entry(checksum: String, lineage: List<String> = emptyList()) = MediaMetadata(
        originalName = "report.txt", relativePath = "Docs", mimeType = "text/plain", size = 1, checksum = checksum,
        encryptedDEK = "k", iv = "i", timestamp = 1, cloudName = "blob_$checksum", lineage = lineage,
    )

    @Test
    fun `an edit wins over the version it was edited from, whatever the batch versions say`() {
        val edited = FolderMetadataBatch("Docs", mapOf("report.txt" to entry("v2-report", listOf("v1-report"))), version = 5,
            replaced = mapOf("blob_v1-report" to ReplacedCopy("v1-report", 50)))
        val lagging = FolderMetadataBatch("Docs", mapOf("report.txt" to entry("v1-report")), version = 6,
            replaced = mapOf("blob_v1-report" to ReplacedCopy("v1-report", 70)))

        val merged = FolderMetadataBatchCodec.merge(listOf(edited, lagging))!!
        assertEquals("v2-report", merged.files.getValue("report.txt").checksum)
        assertEquals(mapOf("blob_v1-report" to ReplacedCopy("v1-report", 50)), merged.replaced)
    }

    @Test
    fun `without an edit between them, the higher version wins as before`() {
        val first = FolderMetadataBatch("Docs", mapOf("report.txt" to entry("v2-report", listOf("v1-report"))), version = 5)
        val other = FolderMetadataBatch("Docs", mapOf("report.txt" to entry("v9-report")), version = 6)
        assertEquals("v9-report", FolderMetadataBatchCodec.merge(listOf(first, other))!!.files.getValue("report.txt").checksum)
    }
}
