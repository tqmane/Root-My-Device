package dev.tqmane.rootmynothing

import android.app.Application
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class OneButtonIntegrationTest {
    @Test
    fun rootAndLateLoadViaShizukuShell() = runBlocking {
        val app = ApplicationProvider.getApplicationContext<Application>()
        val viewModel = RootViewModel(app)
        val ready = withTimeout(30_000) {
            viewModel.state.first {
                it.stage == RootStage.Ready ||
                    it.stage == RootStage.Success ||
                    it.stage == RootStage.Failed
            }
        }
        assertTrue(ready.compatibility.mismatches.joinToString("\n"), ready.compatibility.compatible)
        assertFalse("KernelSU must be absent at the start of this stock-boot test", ready.kernelSuActive)

        viewModel.startRoot()
        val result = withTimeout(30 * 60_000L) {
            viewModel.state.first {
                it.stage == RootStage.Success || it.stage == RootStage.Failed
            }
        }
        File(app.filesDir, "one-button-integration.log").writeText(result.fullLog)
        assertEquals(result.fullLog, RootStage.Success, result.stage)
        assertTrue(result.fullLog, result.kernelSuActive)
        assertTrue(result.fullLog, result.moduleStagesCompleted)
    }
}
