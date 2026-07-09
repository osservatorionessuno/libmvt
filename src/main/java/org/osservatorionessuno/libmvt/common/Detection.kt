package org.osservatorionessuno.libmvt.common

import org.json.JSONArray
import org.json.JSONObject

enum class AlertLevel(val level: Int) {
    LOG(5), // Something to report but not a real alert
    INFO(4),
    LOW(3),
    MEDIUM(2),
    HIGH(1),
    CRITICAL(0),
}

enum class DetectionType(
    val id: String,
    val level: AlertLevel,
    val titleKey: String,
    val contextKey: String,
) {
    IOC_MATCH(
        "ioc_match",
        AlertLevel.CRITICAL,
        "mvt_ioc_title",
        "mvt_ioc_message",
    ),
    ADB_FINGERPRINT(
        "adb_fingerprint",
        AlertLevel.INFO,
        "mvt_adb_fingerprint_title",
        "mvt_adb_fingerprint_message",
    ),
    APPOPS_RISKY_PERMISSION(
        "appops_risky_permission",
        AlertLevel.MEDIUM,
        "mvt_appops_risky_permission_title",
        "mvt_appops_risky_permission_message",
    ),
    PACKAGES_ROOT_PACKAGE(
        "packages_root_package",
        AlertLevel.MEDIUM,
        "mvt_packages_root_package_title",
        "mvt_packages_root_package_message",
    ),
    GETPROP_SECURITY_PATCH(
        "getprop_security_patch",
        AlertLevel.MEDIUM,
        "mvt_getprop_security_patch_title",
        "mvt_getprop_security_patch_message",
    ),
    MOUNTS_ROOT(
        "mounts_root",
        AlertLevel.HIGH,
        "mvt_mounts_root_title",
        "mvt_mounts_root_message",
    ),
    MOUNTS_SYSTEM(
        "mounts_system",
        AlertLevel.HIGH,
        "mvt_mounts_system_title",
        "mvt_mounts_system_message",
    ),
    MOUNTS_SUSPICIOUS(
        "mounts_suspicious",
        AlertLevel.LOW,
        "mvt_mounts_suspicious_title",
        "mvt_mounts_suspicious_message",
    ),
    MOUNTS_DATA(
        "mounts_data",
        AlertLevel.LOG,
        "mvt_mounts_data_title",
        "mvt_mounts_data_message",
    ),
    DANGEROUS_SETTINGS(
        "dangerous_settings",
        AlertLevel.INFO,
        "mvt_dangerous_settings_title",
        "mvt_dangerous_settings_message",
    ),
    TOMBSTONE_CRASHES_UID(
        "tombstone_crashes_uid",
        AlertLevel.MEDIUM,
        "mvt_tombstone_crashes_uid_title",
        "mvt_tombstone_crashes_uid_message",
    ),
    FILES_SUSPICIOUS_PATH(
        "files_suspicious_path",
        AlertLevel.HIGH,
        "mvt_files_suspicious_path_title",
        "mvt_files_suspicious_path_message",
    ),
    PACKAGES_ADB_INSTALLED(
        "packages_adb_installed",
        AlertLevel.HIGH,
        "mvt_packages_non_system_package_title",
        "mvt_packages_non_system_package_message",
    ),
    PACKAGES_THIRD_PARTY_STORE_INSTALLED(
        "packages_third_party_store_installed",
        AlertLevel.INFO,
        "mvt_packages_third_party_store_package_title",
        "mvt_packages_third_party_store_package_message",
    ),
    PACKAGES_BROWSER_INSTALLED(
        "packages_browser_installed",
        AlertLevel.MEDIUM,
        "mvt_packages_browser_package_title",
        "mvt_packages_browser_package_message",
    ),
    PACKAGES_SECURITY_DISABLED(
        "packages_security_disabled",
        AlertLevel.MEDIUM,
        "mvt_packages_security_package_title",
        "mvt_packages_security_package_message",
    ),
    PACKAGES_SYSTEM_UPDATE_DISABLED(
        "packages_system_update_disabled",
        AlertLevel.MEDIUM,
        "mvt_packages_system_update_package_title",
        "mvt_packages_system_update_package_message",
    ),
    DUMPSYS_RECEIVERS_OUTGOING_SMS(
        "dumpsys_receivers_outgoing_sms",
        AlertLevel.LOG,
        "mvt_dumpsys_receivers_intercept_outgoing_sms_title",
        "mvt_dumpsys_receivers_intercept_outgoing_sms_title",
    ),
    DUMPSYS_RECEIVERS_INCOMING_SMS(
        "dumpsys_receivers_incoming_sms",
        AlertLevel.LOG,
        "mvt_dumpsys_receivers_intercept_incoming_sms_title",
        "mvt_dumpsys_receivers_intercept_incoming_sms_title",
    ),
    DUMPSYS_RECEIVERS_DATA_SMS(
        "dumpsys_receivers_data_sms",
        AlertLevel.LOG,
        "mvt_dumpsys_receivers_intercept_data_sms_title",
        "mvt_dumpsys_receivers_intercept_data_sms_message",
    ),
    DUMPSYS_RECEIVERS_PHONE_STATE(
        "dumpsys_receivers_phone_state",
        AlertLevel.LOG,
        "mvt_dumpsys_receivers_intercept_phone_state_title",
        "mvt_dumpsys_receivers_intercept_phone_state_message",
    ),
    DUMPSYS_RECEIVERS_OUTGOING_CALL(
        "dumpsys_receivers_outgoing_call",
        AlertLevel.LOG,
        "mvt_dumpsys_receivers_intercept_outgoing_call_title",
        "mvt_dumpsys_receivers_intercept_outgoing_call_message",
    ),
    ROOT_BINARIES(
        "root_binaries",
        AlertLevel.HIGH,
        "mvt_root_binaries_title",
        "mvt_root_binaries_message",
    ),
    SELINUX_STATUS(
        "selinux_status",
        AlertLevel.HIGH,
        "mvt_selinux_status_title",
        "mvt_selinux_status_message",
    ),
    ANR(
        "anr",
        AlertLevel.MEDIUM,
        "mvt_anr_package_name_title",
        "mvt_anr_package_name_message",
    ),
    ;

    companion object {
        private val byId = entries.associateBy { it.id }

        @JvmStatic
        fun fromId(id: String): DetectionType? = byId[id]

        @JvmStatic
        fun isKnown(id: String): Boolean = id in byId
    }
}

data class Detection(
    val id: String,
    val value: List<String>,
) {
    constructor(type: DetectionType, value: String) : this(type.id, listOf(value))

    constructor(type: DetectionType, vararg values: String) : this(type.id, values.toList())

    constructor(type: DetectionType, values: List<String>) : this(type.id, values)

    override fun toString(): String = "Detection(id='$id', value=$value)"
}

data class GroupedDetection(
    val id: String,
    val detections: List<Entry>,
) {
    constructor(type: DetectionType, detections: List<Entry>) : this(type.id, detections)

    data class Entry(
        val value: List<String>,
        val file: String? = null,
    ) {
        constructor(value: String, file: String? = null) : this(listOf(value), file)
    }

    companion object {
        @JvmStatic
        fun group(
            detections: Iterable<Detection>,
            file: String? = null,
        ): List<GroupedDetection> = buildGrouped(detections) { detection ->
            detection.value to file
        }

        @JvmStatic
        fun fromArtifacts(results: Map<String, Artifact>): List<GroupedDetection> {
            val grouped = LinkedHashMap<String, LinkedHashMap<List<String>, String?>>()
            for ((fileName, artifact) in results) {
                for (detection in artifact.detected) {
                    val bucket = grouped.getOrPut(detection.id) { LinkedHashMap() }
                    addEntry(bucket, detection.value, fileName)
                }
            }
            return toGroupedList(grouped)
        }

        @JvmStatic
        fun toJsonArray(
            grouped: List<GroupedDetection>,
            resolver: StringResolver,
        ): JSONArray {
            val array = JSONArray()
            for (group in grouped) {
                val detectionsArray = JSONArray()
                for (entry in group.detections) {
                    val valueArray = JSONArray()
                    for (part in entry.value) {
                        valueArray.put(part)
                    }
                    val detectionObj = JSONObject()
                    detectionObj.put("value", valueArray)
                    if (entry.file != null) {
                        detectionObj.put("file", entry.file)
                    }
                    detectionsArray.put(detectionObj)
                }

                val (level, title, context) = resolveMetadata(group.id, resolver)
                val obj = JSONObject()
                obj.put("id", group.id)
                obj.put("title", title)
                obj.put("level", level.name)
                obj.put("context", context)
                obj.put("detections", detectionsArray)
                array.put(obj)
            }
            return array
        }

        private fun buildGrouped(
            detections: Iterable<Detection>,
            entryFor: (Detection) -> Pair<List<String>, String?>,
        ): List<GroupedDetection> {
            val grouped = LinkedHashMap<String, LinkedHashMap<List<String>, String?>>()
            for (detection in detections) {
                val bucket = grouped.getOrPut(detection.id) { LinkedHashMap() }
                val (value, file) = entryFor(detection)
                addEntry(bucket, value, file)
            }
            return toGroupedList(grouped)
        }

        private fun addEntry(
            bucket: LinkedHashMap<List<String>, String?>,
            value: List<String>,
            file: String?,
        ) {
            bucket.putIfAbsent(value, file)
        }

        private fun toGroupedList(
            grouped: Map<String, LinkedHashMap<List<String>, String?>>,
        ): List<GroupedDetection> = grouped.map { (id, entries) ->
            GroupedDetection(
                id = id,
                detections = entries.map { (value, entryFile) ->
                    Entry(value = value, file = entryFile)
                },
            )
        }

        private fun resolveMetadata(
            id: String,
            resolver: StringResolver,
        ): Triple<AlertLevel, String, String> {
            val type = DetectionType.fromId(id)
                ?: return Triple(AlertLevel.INFO, "", "")

            return Triple(
                type.level,
                resolveKey(resolver, type.titleKey),
                resolveKey(resolver, type.contextKey),
            )
        }

        private fun resolveKey(resolver: StringResolver, key: String): String {
            if (key.isEmpty()) return ""
            return resolver.get(key).takeIf { it.isNotEmpty() } ?: ""
        }
    }
}
