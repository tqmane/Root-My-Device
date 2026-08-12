package dev.tqmane.rootmyonepluspad3

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class KernelSuLiveGateTest {
    private val liveRecord =
        "kernelsu 163840 1 - Live 0x0000000000000000 (O)\n"

    @Test
    fun directProbeDeniedButGrantedShizukuSeesExactLiveRecord() {
        assertTrue(
            KernelSuLiveGate.active(
                directActive = false,
                shizukuRunning = true,
                shizukuGranted = true,
                procModules = "other 4096 0 - Live 0x0000000000000000\n$liveRecord",
            ),
        )
    }

    @Test
    fun malformedLoadingAndSubstringRecordsFailClosed() {
        val rejected = listOf(
            "kernelsu 163840 1 - Loading 0x0000000000000000 (O)\n",
            "notkernelsu 163840 1 - Live 0x0000000000000000 (O)\n",
            "prefix kernelsu 163840 1 - Live 0x0000000000000000 (O)\n",
            "kernelsu 163840 1 - Live 0x0000000000000000 (O) suffix\n",
            "kernelsu Live\n",
            "",
        )

        rejected.forEach { procModules ->
            assertFalse(
                procModules,
                KernelSuLiveGate.active(
                    directActive = false,
                    shizukuRunning = true,
                    shizukuGranted = true,
                    procModules = procModules,
                ),
            )
        }
    }

    @Test
    fun absentShizukuOrPermissionRejectsShellEvidence() {
        assertFalse(
            KernelSuLiveGate.active(false, false, true, liveRecord),
        )
        assertFalse(
            KernelSuLiveGate.active(false, true, false, liveRecord),
        )
        assertFalse(
            KernelSuLiveGate.active(false, true, true, null),
        )
    }

    @Test
    fun successfulDirectProbeDoesNotDependOnShizuku() {
        assertTrue(
            KernelSuLiveGate.active(true, false, false, null),
        )
    }
}
