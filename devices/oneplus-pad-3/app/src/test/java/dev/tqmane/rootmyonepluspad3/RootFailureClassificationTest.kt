package dev.tqmane.rootmyonepluspad3

import org.junit.Assert.assertEquals
import org.junit.Test

class RootFailureClassificationTest {
    @Test
    fun uuidCollateralFailurePrecedesWrapperExitAndPselect() {
        val log = """
            [*] slide pselect returned ret=5 errno=0
            [!] slide uuid collateral mismatch value=1 want=2
        """.trimIndent()

        assertEquals(
            "SLIDE_UUID_COLLATERAL_MISMATCH",
            classifyFailure("Shizuku payload exited 1", log),
        )
    }

    @Test
    fun uuidRestoreFailurePrecedesGenericCfiFailure() {
        val log = """
            [*] pselect route done calls=1 success=1
            [*] slide restore uuid pid=42 stamped_exact=1 exact=0
            [!] cfi redirect failed
        """.trimIndent()

        assertEquals(
            "SLIDE_UUID_RESTORE_FAILED",
            classifyFailure("Shizuku payload exited 1", log),
        )
    }

    @Test
    fun ordinaryPselectFailureRetainsLegacyClassification() {
        assertEquals(
            "PSELECT_STAGE_FAILED",
            classifyFailure(
                "Shizuku payload exited 1",
                "pselect route failure attempt=1 ret=-1",
            ),
        )
    }
}
