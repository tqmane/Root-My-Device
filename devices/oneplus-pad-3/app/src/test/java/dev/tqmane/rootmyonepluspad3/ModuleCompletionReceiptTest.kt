package dev.tqmane.rootmyonepluspad3

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ModuleCompletionReceiptTest {
    private val bootId = "65bd9f36-07ed-4a45-9d86-02931b5d26d2"
    private val runId = "0123456789abcdef0123456789abcdef"
    private val ksud = "a".repeat(64)
    private val valid = """
        ${ModuleCompletionReceipt.PROBE_REGULAR} uid=0 gid=0 mode=644 nlink=1
        version=1
        boot_id=$bootId
        run_id=$runId
        ksud_sha256=$ksud
    """.trimIndent() + "\n"

    @Test
    fun exactCurrentRequestMatches() {
        assertTrue(ModuleCompletionReceipt.matches(valid, bootId, runId, ksud))
    }

    @Test
    fun probeStatsTheDescriptorOwnedByTheInvokingShell() {
        val command = ModuleCompletionReceipt.probeCommand()

        assertTrue(command.contains("\"/proc/\$\$/fd/3\""))
        assertFalse(command.contains("/proc/self/fd/3"))
        assertTrue(command.contains("/system/bin/cat <&3"))
    }

    @Test
    fun metadataOrAdditionalContentFailsClosed() {
        assertFalse(
            ModuleCompletionReceipt.matches(
                ModuleCompletionReceipt.PROBE_UNSAFE,
                bootId,
                runId,
                ksud,
            ),
        )
        assertFalse(
            ModuleCompletionReceipt.matches(
                valid.replace("uid=0", "uid=2000"),
                bootId,
                runId,
                ksud,
            ),
        )
        assertFalse(ModuleCompletionReceipt.matches(valid + "extra=1\n", bootId, runId, ksud))
    }

    @Test
    fun staleBootNonceOrDaemonFailsClosed() {
        assertFalse(ModuleCompletionReceipt.matches(valid, "old-boot", runId, ksud))
        assertFalse(ModuleCompletionReceipt.matches(valid, bootId, "f".repeat(32), ksud))
        assertFalse(ModuleCompletionReceipt.matches(valid, bootId, runId, "b".repeat(64)))
    }

    @Test
    fun malformedPinsFailClosed() {
        assertFalse(ModuleCompletionReceipt.matches(valid, bootId, "ABC", ksud))
        assertFalse(ModuleCompletionReceipt.matches(valid, bootId, runId, "not-a-digest"))
        assertFalse(ModuleCompletionReceipt.matches(valid, "not-a-boot-id", runId, ksud))
    }
}
