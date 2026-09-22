package dev.tqmane.rootmynothing

import android.os.Build
import android.system.Os
import android.system.OsConstants
import java.io.File

data class DeviceSnapshot(
    val model: String,
    val device: String,
    val display: String,
    val fingerprint: String,
    val kernelRelease: String,
    val sdk: Int,
    val securityPatch: String,
    val pageSize: Long,
    val abi: String,
) {
    companion object {
        fun current(): DeviceSnapshot {
            val uname = Os.uname()
            return DeviceSnapshot(
                model = Build.MODEL,
                device = Build.DEVICE,
                display = Build.DISPLAY,
                fingerprint = Build.FINGERPRINT,
                kernelRelease = uname.release,
                sdk = Build.VERSION.SDK_INT,
                securityPatch = Build.VERSION.SECURITY_PATCH,
                pageSize = Os.sysconf(OsConstants._SC_PAGESIZE),
                abi = Build.SUPPORTED_ABIS.firstOrNull().orEmpty(),
            )
        }
    }
}

data class Compatibility(
    val compatible: Boolean,
    val mismatches: List<String>,
)

object AsteroidsTarget {
    const val MODEL = "A059"
    const val DEVICE = "Asteroids"
    const val KERNEL = "6.1.157-android14-11-g82d681c9b06b-ab14634535"
    const val PAGE_SIZE = 4096L
    const val KMI = "android14-6.1"
    const val MANAGER_PACKAGE = "org.witaqua.pwn.kernelsu"

    // Both builds share the identical kernel image; only the build identity differs.
    data class SupportedBuild(
        val display: String,
        val fingerprint: String,
        val securityPatch: String,
        val sdk: Int,
    )

    const val DISPLAY = "B4.1-260618-1048"
    const val FINGERPRINT =
        "Nothing/AsteroidsJPN/Asteroids:16/BQ2A.250721.001-" +
            "BP2A.250605.031.A3/2606181048:user/release-keys"
    const val SECURITY_PATCH = "2026-06-01"
    const val DISPLAY_260810 = "B4.1-260810-1153"
    const val FINGERPRINT_260810 =
        "Nothing/AsteroidsJPN/Asteroids:16/BQ2A.250721.001-" +
            "BP2A.250605.031.A3/2608101153:user/release-keys"
    const val SECURITY_PATCH_260810 = "2026-08-01"
    const val DISPLAY_260915 = "C5.0-260915-2123"
    const val FINGERPRINT_260915 =
        "Nothing/AsteroidsJPN/Asteroids:17/CQ2A.260522.002-" +
            "CP2A.260605.016/2609152123:user/release-keys"
    const val SECURITY_PATCH_260915 = "2026-09-01"

    val SUPPORTED_BUILDS = listOf(
        SupportedBuild(DISPLAY, FINGERPRINT, SECURITY_PATCH, 36),
        SupportedBuild(DISPLAY_260810, FINGERPRINT_260810, SECURITY_PATCH_260810, 36),
        SupportedBuild(DISPLAY_260915, FINGERPRINT_260915, SECURITY_PATCH_260915, 37),
    )

    private val SUPPORTED_DISPLAYS = SUPPORTED_BUILDS.map { it.display }
    private val SUPPORTED_PATCHES = SUPPORTED_BUILDS.map { it.securityPatch }

    fun validate(snapshot: DeviceSnapshot): Compatibility {
        val mismatches = buildList {
            if (snapshot.model != MODEL) add("MODEL=${snapshot.model} (expected $MODEL)")
            if (snapshot.device != DEVICE) add("DEVICE=${snapshot.device} (expected $DEVICE)")
            if (snapshot.kernelRelease != KERNEL) {
                add("KERNEL=${snapshot.kernelRelease} (expected $KERNEL)")
            }
            if (snapshot.pageSize != PAGE_SIZE) {
                add("PAGE=${snapshot.pageSize} (expected $PAGE_SIZE)")
            }
            if (snapshot.abi != "arm64-v8a") add("ABI=${snapshot.abi} (expected arm64-v8a)")
            val build = SUPPORTED_BUILDS.firstOrNull {
                it.display == snapshot.display &&
                    it.fingerprint == snapshot.fingerprint &&
                    it.securityPatch == snapshot.securityPatch &&
                    it.sdk == snapshot.sdk
            }
            if (build == null) {
                if (SUPPORTED_BUILDS.none { it.display == snapshot.display }) {
                    add("BUILD=${snapshot.display} (expected one of ${SUPPORTED_DISPLAYS.joinToString()})")
                }
                if (SUPPORTED_BUILDS.none { it.fingerprint == snapshot.fingerprint }) {
                    add("FINGERPRINT mismatch")
                }
                if (SUPPORTED_BUILDS.none { it.securityPatch == snapshot.securityPatch }) {
                    add("SECURITY_PATCH=${snapshot.securityPatch} (expected one of ${SUPPORTED_PATCHES.joinToString()})")
                }
                if (SUPPORTED_BUILDS.none { it.sdk == snapshot.sdk }) {
                    add("SDK=${snapshot.sdk} (expected one of ${SUPPORTED_BUILDS.map { it.sdk }.distinct().joinToString()})")
                }
                if (isEmpty()) {
                    add("BUILD/FINGERPRINT/SECURITY_PATCH do not form one supported set (${SUPPORTED_DISPLAYS.joinToString()})")
                }
            }
        }
        return Compatibility(mismatches.isEmpty(), mismatches)
    }
}

object KernelSuDetector {
    fun active(): Boolean {
        if (File("/sys/module/kernelsu").exists()) return true
        return runCatching {
            File("/proc/modules").useLines { lines ->
                lines.any { it.startsWith("kernelsu ") }
            }
        }.getOrDefault(false)
    }

    fun bootId(): String? = runCatching {
        File("/proc/sys/kernel/random/boot_id")
            .readText(Charsets.US_ASCII)
            .trim()
            .takeIf(String::isNotBlank)
    }.getOrNull()
}
