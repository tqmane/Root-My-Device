package dev.tqmane.rootmyonepluspad3

import android.os.Build
import android.system.Os
import android.system.OsConstants
import java.io.File

data class DeviceSnapshot(
    val model: String,
    val device: String,
    val product: String,
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
                product = Build.PRODUCT,
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

object OnePlusPad3Target {
    const val ID = "oneplus-pad3-ex-16.0.9.400"
    const val MODEL = "OPD2415"
    const val DEVICE = "OP6190L1"
    const val PRODUCT = "OPD2415IN"
    const val DISPLAY = "OPD2415_16.0.9.400(EX01)"
    const val KERNEL = "6.6.118-android15-8-g2e6b9c3812c5-ab15114928-4k"
    const val FINGERPRINT =
        "OnePlus/OPD2415IN/OP6190L1:16/AP3A.240617.008/" +
            "V.R4T3.17bf73d_cf42a1_c9913b:user/release-keys"
    const val SDK = 36
    const val SECURITY_PATCH = "2026-07-01"
    const val PAGE_SIZE = 4096L
    const val KMI = "android15-6.6"
    const val MANAGER_PACKAGE = "org.witaqua.pwn.kernelsu"

    fun validate(snapshot: DeviceSnapshot): Compatibility {
        val mismatches = buildList {
            if (snapshot.model != MODEL) add("MODEL=${snapshot.model} (expected $MODEL)")
            if (snapshot.device != DEVICE) add("DEVICE=${snapshot.device} (expected $DEVICE)")
            if (snapshot.product != PRODUCT) {
                add("PRODUCT=${snapshot.product} (expected $PRODUCT)")
            }
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

/**
 * Fail-closed policy for the shell-assisted KernelSU live probe.
 *
 * Some production SELinux policies hide `/proc/modules` from an untrusted app
 * even though the same file is readable by Shizuku's shell domain.  The
 * fallback is accepted only when Shizuku is both live and already granted, and
 * only for a complete `kernelsu ... Live ...` `/proc/modules` record.
 */
internal object KernelSuLiveGate {
    private val liveKernelSuRecord = Regex(
        "^kernelsu [1-9][0-9]* [0-9]+ " +
            "(?:-|[A-Za-z0-9_.-]+(?:,[A-Za-z0-9_.-]+)*,?) " +
            "Live 0x[0-9A-Fa-f]{16}(?: \\([A-Z]+\\))?$",
    )

    fun active(
        directActive: Boolean,
        shizukuRunning: Boolean,
        shizukuGranted: Boolean,
        procModules: String?,
    ): Boolean {
        if (directActive) return true
        if (!shizukuRunning || !shizukuGranted || procModules == null) return false
        return procModules.lineSequence().any(liveKernelSuRecord::matches)
    }
}
