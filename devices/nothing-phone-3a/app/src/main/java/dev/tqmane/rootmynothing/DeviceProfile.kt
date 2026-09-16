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
    const val DISPLAY = "B4.1-260618-1048"
    const val KERNEL = "6.1.157-android14-11-g82d681c9b06b-ab14634535"
    const val FINGERPRINT =
        "Nothing/AsteroidsJPN/Asteroids:16/BQ2A.250721.001-" +
            "BP2A.250605.031.A3/2606181048:user/release-keys"
    const val SDK = 36
    const val SECURITY_PATCH = "2026-06-01"
    const val PAGE_SIZE = 4096L
    const val KMI = "android14-6.1"
    const val MANAGER_PACKAGE = "org.witaqua.pwn.kernelsu"

    fun validate(snapshot: DeviceSnapshot, checksEnabled: Boolean = true): Compatibility {
        if (!checksEnabled) return Compatibility(true, emptyList())

        val mismatches = buildList {
            if (snapshot.model != MODEL) add("MODEL=${snapshot.model} (expected $MODEL)")
            if (snapshot.device != DEVICE) add("DEVICE=${snapshot.device} (expected $DEVICE)")
            if (snapshot.display != DISPLAY) add("BUILD=${snapshot.display} (expected $DISPLAY)")
            if (snapshot.fingerprint != FINGERPRINT) add("FINGERPRINT mismatch")
            if (snapshot.kernelRelease != KERNEL) {
                add("KERNEL=${snapshot.kernelRelease} (expected $KERNEL)")
            }
            if (snapshot.sdk != SDK) add("SDK=${snapshot.sdk} (expected $SDK)")
            if (snapshot.securityPatch != SECURITY_PATCH) {
                add("SECURITY_PATCH=${snapshot.securityPatch} (expected $SECURITY_PATCH)")
            }
            if (snapshot.pageSize != PAGE_SIZE) {
                add("PAGE=${snapshot.pageSize} (expected $PAGE_SIZE)")
            }
            if (snapshot.abi != "arm64-v8a") add("ABI=${snapshot.abi} (expected arm64-v8a)")
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
