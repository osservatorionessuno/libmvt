package org.osservatorionessuno.libmvt.common

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import org.osservatorionessuno.libmvt.common.JvmMapStringResolver

class GroupedDetectionTest {

    private fun stubArtifact(vararg detections: Detection) = object : Artifact() {
        override fun parse(artifactInput: AbstractInput) = Unit
        override fun checkIndicators() = Unit
    }.apply {
        this.detected.addAll(detections)
    }

    @Test
    fun group_groupsByIdAndDeduplicates() {
        val detections = listOf(
            Detection(DetectionType.ROOT_BINARIES, "su", "/system/xbin/su"),
            Detection(DetectionType.ROOT_BINARIES, "su", "/sbin/su"),
            Detection(DetectionType.ROOT_BINARIES, "su", "/system/xbin/su"),
            Detection(DetectionType.IOC_MATCH, "APP_ID", "evil.apk", "evil.apk"),
        )

        val grouped = GroupedDetection.group(detections, "root_binaries.json")

        assertEquals(2, grouped.size)
        assertEquals(DetectionType.ROOT_BINARIES.id, grouped[0].id)
        assertEquals(2, grouped[0].detections.size)
        assertEquals(listOf("su", "/system/xbin/su"), grouped[0].detections[0].value)
        assertEquals("root_binaries.json", grouped[0].detections[0].file)
        assertEquals(DetectionType.IOC_MATCH.id, grouped[1].id)
        assertEquals(listOf("APP_ID", "evil.apk", "evil.apk"), grouped[1].detections.single().value)
    }

    @Test
    fun fromArtifacts_deduplicatesSameValueAcrossFiles() {
        val artifactA = stubArtifact(
            Detection(DetectionType.ROOT_BINARIES, "su", "/system/xbin/su"),
        )
        val artifactB = stubArtifact(
            Detection(DetectionType.ROOT_BINARIES, "su", "/system/xbin/su"),
        )

        val grouped = GroupedDetection.fromArtifacts(
            mapOf("a.json" to artifactA, "b.json" to artifactB),
        )

        assertEquals(1, grouped.size)
        assertEquals(1, grouped[0].detections.size)
        assertEquals(listOf("su", "/system/xbin/su"), grouped[0].detections[0].value)
        assertEquals("a.json", grouped[0].detections[0].file)
    }

    @Test
    fun fromArtifacts_keepsDistinctValuesAcrossFiles() {
        val artifactA = stubArtifact(
            Detection(DetectionType.ROOT_BINARIES, "su", "/system/xbin/su"),
        )
        val artifactB = stubArtifact(
            Detection(DetectionType.ROOT_BINARIES, "su", "/sbin/su"),
        )

        val grouped = GroupedDetection.fromArtifacts(
            mapOf("a.json" to artifactA, "b.json" to artifactB),
        )

        assertEquals(1, grouped.size)
        assertEquals(2, grouped[0].detections.size)
        assertEquals("a.json", grouped[0].detections[0].file)
        assertEquals("b.json", grouped[0].detections[1].file)
    }

    @Test
    fun toJsonArray_resolvesMetadataWithoutCount() {
        val grouped = listOf(
            GroupedDetection(
                id = DetectionType.ROOT_BINARIES.id,
                detections = listOf(
                    GroupedDetection.Entry(listOf("su", "/system/xbin/su"), "root_binaries.json"),
                ),
            ),
        )

        val array = GroupedDetection.toJsonArray(grouped, JvmMapStringResolver())
        val obj = array.getJSONObject(0)

        assertEquals("root_binaries", obj.getString("id"))
        assertEquals("HIGH", obj.getString("level"))
        assertFalse(obj.has("count"))
        assertEquals(1, obj.getJSONArray("detections").length())
        assertEquals("su", obj.getJSONArray("detections").getJSONObject(0).getJSONArray("value").getString(0))
        assertEquals("/system/xbin/su", obj.getJSONArray("detections").getJSONObject(0).getJSONArray("value").getString(1))
        assertFalse(obj.getJSONArray("detections").getJSONObject(0).has("context"))
    }

    @Test
    fun toJsonArray_unknownIdUsesInfoWithEmptyMetadata() {
        val grouped = listOf(
            GroupedDetection(
                id = "future_module_finding",
                detections = listOf(GroupedDetection.Entry(listOf("some-value"))),
            ),
        )

        val obj = GroupedDetection.toJsonArray(grouped, JvmMapStringResolver()).getJSONObject(0)

        assertEquals("future_module_finding", obj.getString("id"))
        assertEquals("INFO", obj.getString("level"))
        assertEquals("", obj.getString("title"))
        assertEquals("", obj.getString("context"))
    }
}
