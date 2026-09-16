package dev.tqmane.rootmynothing

import android.app.Application
import android.os.SystemClock
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

enum class RootStage {
    Checking,
    Ready,
    Extracting,
    Exploiting,
    TemporaryRoot,
    LoadingKernelSu,
    Verifying,
    StartingModules,
    Success,
    Failed,
}

data class RootUiState(
    val snapshot: DeviceSnapshot? = null,
    val compatibility: Compatibility = Compatibility(false, emptyList()),
    val compatibilityChecksEnabled: Boolean = true,
    val stage: RootStage = RootStage.Checking,
    val status: String = "Checking device",
    val kernelSuActive: Boolean = false,
    val modulesRequested: Boolean = false,
    val moduleStagesCompleted: Boolean = false,
    val fullLog: String = "",
    val visibleLog: String = "",
    val errorCode: String? = null,
) {
    val busy: Boolean
        get() = stage in setOf(
            RootStage.Checking,
            RootStage.Extracting,
            RootStage.Exploiting,
            RootStage.TemporaryRoot,
            RootStage.LoadingKernelSu,
            RootStage.Verifying,
            RootStage.StartingModules,
        )
}

private data class CommandResult(val code: Int, val output: String)

private enum class LateLoadRoute {
    BootstrapHelper,
    KernelSu,
}

class RootViewModel(application: Application) : AndroidViewModel(application) {
    private val preferences = application.getSharedPreferences(PREFERENCES_NAME, 0)
    private val app = application
    private val mutableState = MutableStateFlow(RootUiState())
    private val operationInFlight = AtomicBoolean(false)
    val state: StateFlow<RootUiState> = mutableState.asStateFlow()

    init {
        refresh()
    }

    fun refresh() {
        if (
            (mutableState.value.busy && mutableState.value.stage != RootStage.Checking) ||
            !operationInFlight.compareAndSet(false, true)
        ) {
            return
        }
        viewModelScope.launch(Dispatchers.IO) {
            val snapshot = DeviceSnapshot.current()
            val compatibilityChecksEnabled = preferences.getBoolean(COMPATIBILITY_CHECKS_KEY, true)
            val compatibility = AsteroidsTarget.validate(snapshot, compatibilityChecksEnabled)
            val markerCompleted = moduleMarkerMatchesBoot()
            if (markerCompleted && !moduleStagesCompletedReceiptThisBoot()) {
                storeVerifiedReceipt(modulesRequested = true, modulesCompleted = true)
            }
            val active = KernelSuDetector.active() || verifiedThisBoot() || markerCompleted
            val modulesRequested = active && modulesRequestedThisBoot()
            val moduleStagesCompleted = active &&
                (moduleStagesCompletedReceiptThisBoot() || markerCompleted)
            val log = buildString {
                appendLine("[*] MODEL=${snapshot.model} DEVICE=${snapshot.device}")
                appendLine(
                    "[*] BUILD=${snapshot.display} SDK=${snapshot.sdk} " +
                        "SECURITY_PATCH=${snapshot.securityPatch}",
                )
                appendLine("[*] FINGERPRINT=${snapshot.fingerprint}")
                appendLine(
                    "[*] KERNEL=${snapshot.kernelRelease} PAGE=${snapshot.pageSize} " +
                        "ABI=${snapshot.abi}",
                )
                if (compatibility.compatible) {
                    append("[+] exact Asteroids target matched")
                } else {
                    compatibility.mismatches.forEach { appendLine("[-] $it") }
                }
                if (active) appendLine().append("[+] KernelSU is active")
                if (moduleStagesCompleted) {
                    appendLine().append("[+] late-load module stages completed in this boot")
                } else if (modulesRequested) {
                    appendLine().append("[!] late-load module stages requested but completion is unverified")
                }
            }
            mutableState.value = RootUiState(
                snapshot = snapshot,
                compatibility = compatibility,
                compatibilityChecksEnabled = compatibilityChecksEnabled,
                stage = if (active) RootStage.Success else if (compatibility.compatible) {
                    RootStage.Ready
                } else {
                    RootStage.Failed
                },
                status = when {
                    active && moduleStagesCompleted -> "KernelSU active · module stages complete"
                    active && modulesRequested -> "KernelSU active · module completion unverified"
                    active -> "KernelSU active"
                    compatibility.compatible -> "Ready"
                    else -> "Target mismatch"
                },
                kernelSuActive = active,
                modulesRequested = modulesRequested,
                moduleStagesCompleted = moduleStagesCompleted,
                fullLog = log,
                visibleLog = sanitize(log),
                errorCode = if (compatibility.compatible) null else "TARGET_MISMATCH",
            )
        }.invokeOnCompletion {
            operationInFlight.set(false)
        }
    }

    fun setCompatibilityChecksEnabled(enabled: Boolean) {
        if (mutableState.value.busy) return
        preferences.edit().putBoolean(COMPATIBILITY_CHECKS_KEY, enabled).apply()
        refresh()
    }

    fun startRoot() {
        val current = mutableState.value
        if (
            current.busy || current.kernelSuActive || !current.compatibility.compatible ||
            !operationInFlight.compareAndSet(false, true)
        ) {
            return
        }
        viewModelScope.launch(Dispatchers.IO) {
            try {
                update(RootStage.Extracting, "Connecting to Shizuku")
                ensureShizukuShell()
                appendLog("[+] Shizuku shell permission verified")

                val existingKernelSuRoot = kernelSuRootAvailable()
                update(RootStage.Extracting, "Preparing verified native payloads")
                val artifacts = ArtifactStore.prepare(app, ::appendLog)

                val lateLoadRoute = if (!existingKernelSuRoot) {
                    update(RootStage.Exploiting, "Running CVE-2026-43499")
                    runExploit(artifacts)
                    update(RootStage.TemporaryRoot, "Temporary root acquired")
                    appendLog("[+] temporary root markers verified")
                    LateLoadRoute.BootstrapHelper
                } else {
                    update(RootStage.TemporaryRoot, "Existing KernelSU root detected")
                    appendLog(
                        "[+] uid=0 verified through su -M; " +
                            "skipping exploit/helper staging and resuming through KernelSU",
                    )
                    LateLoadRoute.KernelSu
                }

                stageKernelSuAndModules(artifacts, lateLoadRoute)
            } catch (error: Throwable) {
                recordFailure(error)
            }
        }.invokeOnCompletion {
            operationInFlight.set(false)
        }
    }

    fun retryModuleStages() {
        val current = mutableState.value
        if (
            current.busy || !current.kernelSuActive || current.moduleStagesCompleted ||
            !current.compatibility.compatible ||
            !operationInFlight.compareAndSet(false, true)
        ) {
            return
        }
        viewModelScope.launch(Dispatchers.IO) {
            try {
                update(RootStage.Extracting, "Connecting to Shizuku")
                ensureShizukuShell()
                appendLog("[+] Shizuku shell permission verified")

                require(kernelSuRootAvailable()) {
                    "KernelSU su -M root access is unavailable from the Shizuku shell"
                }
                appendLog("[+] uid=0 verified through KernelSU su -M")

                update(RootStage.Extracting, "Preparing verified KernelSU payload")
                val artifacts = ArtifactStore.prepare(app, ::appendLog)
                appendLog("[+] bootstrap helper is not used for this enforcing-state retry")
                stageKernelSuAndModules(artifacts, LateLoadRoute.KernelSu)
            } catch (error: Throwable) {
                recordFailure(error)
            }
        }.invokeOnCompletion {
            operationInFlight.set(false)
        }
    }

    private suspend fun stageKernelSuAndModules(
        artifacts: RuntimeArtifacts,
        route: LateLoadRoute,
    ) {
        if (route == LateLoadRoute.KernelSu) {
            if (acceptCurrentBootModuleMarker()) return
            require(!kernelSuLateLoadActive()) {
                "A previous KernelSU late-load is still running; wait for it to finish, then refresh"
            }
        }

        update(RootStage.LoadingKernelSu, "Staging KernelSU")
        stageKernelSu(artifacts)
        appendLog("[+] ksud staged at /data/local/tmp/ksud")
        if (route == LateLoadRoute.KernelSu) {
            shizukuStage(artifacts.ksud, SHIZUKU_KSUD_STAGE_PATH, "755")
            appendLog("[+] ksud install image staged at /data/local/tmp/.ksud-stage")
        }

        update(RootStage.StartingModules, "Late-loading KernelSU with module stages")
        storeModuleRequestReceipt()
        removeModuleCompletionMarker()

        var commandFailure: Throwable? = null
        val lateLoad = try {
            when (route) {
                LateLoadRoute.BootstrapHelper -> runHelper(
                    "--late-load",
                    AsteroidsTarget.KMI,
                    AsteroidsTarget.MANAGER_PACKAGE,
                    "modules",
                )
                LateLoadRoute.KernelSu -> runKernelSuLateLoad()
            }
        } catch (error: Throwable) {
            commandFailure = error
            appendLog(
                "[!] late-load command channel was interrupted; " +
                    "waiting for the current-boot completion marker: " +
                    (error.message ?: error.javaClass.simpleName),
            )
            null
        }
        if (lateLoad?.output?.isNotBlank() == true) appendLog(lateLoad.output)
        if (lateLoad != null && lateLoad.code != 0) {
            error("KernelSU late-load/module stages failed (rc=${lateLoad.code}): ${lateLoad.output}")
        }

        val markerCompleted = awaitModuleCompletionMarker()
        if (!markerCompleted) {
            val reason = commandFailure?.message?.let { "; command channel error: $it" }.orEmpty()
            error(
                "KernelSU late-load did not publish the current-boot module completion marker" +
                    reason,
            )
        }
        if (commandFailure != null) {
            appendLog("[+] module marker verified after the command channel interruption")
        }
        storeVerifiedReceipt(modulesRequested = true, modulesCompleted = true)
        delay(500)

        appendLog("[+] KernelSU control channel verified")
        appendLog("[+] late-load module stages completed; zygote boundary recreated")
        mutableState.value = mutableState.value.copy(
            stage = RootStage.Success,
            status = "KernelSU active · module stages complete",
            kernelSuActive = true,
            modulesRequested = true,
            moduleStagesCompleted = true,
            errorCode = null,
        )
    }

    private fun acceptCurrentBootModuleMarker(): Boolean {
        if (!moduleMarkerMatchesBoot()) return false
        storeVerifiedReceipt(modulesRequested = true, modulesCompleted = true)
        appendLog("[+] existing current-boot module completion marker verified")
        mutableState.value = mutableState.value.copy(
            stage = RootStage.Success,
            status = "KernelSU active · module stages complete",
            kernelSuActive = true,
            modulesRequested = true,
            moduleStagesCompleted = true,
            errorCode = null,
        )
        return true
    }

    private suspend fun runExploit(artifacts: RuntimeArtifacts) {
        shizukuStage(artifacts.helper, SHIZUKU_HELPER_PATH, "755")
        shizukuStage(artifacts.payload, SHIZUKU_PAYLOAD_PATH, "755")
        appendLog("[+] standalone payload staged through Shizuku")

        val prefix = mutableState.value.fullLog
        val started = SystemClock.elapsedRealtime()
        ShizukuController.exec(
            arrayOf("/system/bin/rm", "-f", SHIZUKU_LOG_PATH),
        ).waitFor()
        val process = ShizukuController.exec(
            arrayOf("/system/bin/sh", "-c", SHIZUKU_EXPLOIT_COMMAND),
            arrayOf(
                "EXPLOIT_ATTEMPTS=24",
                "EXPLOIT_ATTEMPT_TIMEOUT_SEC=300",
            ),
            "/data/local/tmp",
        )

        var lastRaw = ""
        while (runCatching { process.isAlive }.getOrDefault(false)) {
            val raw = ShizukuController.capture(
                arrayOf("/system/bin/cat", SHIZUKU_LOG_PATH),
            )
            if (raw != lastRaw) {
                publishExploitLog(prefix, raw)
                lastRaw = raw
            }
            val elapsedMinutes =
                (SystemClock.elapsedRealtime() - started) / 60_000
            if (elapsedMinutes > 0 && elapsedMinutes % 5L == 0L) {
                mutableState.value = mutableState.value.copy(
                    status = "Shizuku exploit running (${elapsedMinutes} min)",
                )
            }
            delay(1_000)
        }

        val code = process.waitFor()
        val raw = ShizukuController.capture(
            arrayOf("/system/bin/cat", SHIZUKU_LOG_PATH),
        )
        publishExploitLog(prefix, raw)
        require(code == 0) { "Shizuku payload exited $code" }
        require(raw.contains("done=1 root=1")) { "Temporary root success marker missing" }
        require(raw.contains("exploit completed")) { "Exploit completion marker missing" }
    }

    private fun stageKernelSu(artifacts: RuntimeArtifacts) {
        shizukuStage(artifacts.ksud, SHIZUKU_KSUD_PATH, "755")
    }

    private fun runHelper(vararg arguments: String): CommandResult {
        return runCommand(arrayOf(SHIZUKU_HELPER_PATH) + arguments)
    }

    private fun runKernelSuLateLoad(): CommandResult {
        val ksudCommand = listOf(
            SHIZUKU_KSUD_PATH,
            "late-load",
            "--kmi",
            AsteroidsTarget.KMI,
            "--package-name",
            AsteroidsTarget.MANAGER_PACKAGE,
            "--modules",
        ).joinToString(" ", transform = ::shellQuote)
        val command = "su -M -c ${shellQuote(ksudCommand)}"
        return runCommand(arrayOf("/system/bin/sh", "-c", command))
    }

    private fun removeModuleCompletionMarker() {
        val result = runCommand(
            arrayOf(
                "/system/bin/rm",
                "-f",
                SHIZUKU_MODULE_STATUS_PATH,
            ),
        )
        require(result.code == 0) {
            "Unable to clear the previous module completion marker: ${result.output}"
        }
    }

    private fun runCommand(command: Array<String>): CommandResult {
        val process = ShizukuController.exec(command)
        var stdout = ""
        var stderr = ""
        val stdoutReader = thread(isDaemon = true, name = "shizuku-command-stdout") {
            stdout = runCatching {
                process.inputStream.bufferedReader().use { it.readText() }
            }.getOrDefault("")
        }
        val stderrReader = thread(isDaemon = true, name = "shizuku-command-stderr") {
            stderr = runCatching {
                process.errorStream.bufferedReader().use { it.readText() }
            }.getOrDefault("")
        }
        val code = try {
            process.waitFor()
        } finally {
            runCatching { if (process.isAlive) process.destroy() }
            runCatching { stdoutReader.join(STREAM_READER_JOIN_MILLIS) }
            runCatching { stderrReader.join(STREAM_READER_JOIN_MILLIS) }
        }
        return CommandResult(code, stripAnsi(stdout + stderr).trim())
    }

    private fun kernelSuRootAvailable(): Boolean {
        val result = runCommand(
            arrayOf(
                "/system/bin/sh",
                "-c",
                "su -M -c /system/bin/id",
            ),
        )
        return when (result.code) {
            0 -> {
                require(ROOT_IDENTITY.containsMatchIn(result.output)) {
                    "KernelSU su -M completed without a uid=0 identity: ${result.output}"
                }
                true
            }
            SHELL_COMMAND_NOT_FOUND -> false
            else -> error(
                "Unable to determine KernelSU su -M root state " +
                    "(rc=${result.code}): ${result.output}",
            )
        }
    }

    private fun kernelSuLateLoadActive(): Boolean {
        val scan = """
            [ -r /proc/1/comm ] || exit 43
            [ -x /system/bin/xargs ] || exit 44
            for proc in /proc/[0-9]*; do
                comm=
                IFS= read -r comm < "${'$'}proc/comm" 2>/dev/null || continue
                case "${'$'}comm" in
                    ksud|logcat)
                        args=${'$'}(/system/bin/xargs -0 /system/bin/echo < "${'$'}proc/cmdline" 2>/dev/null) || continue
                        case "${'$'}args" in
                            *" late-load "*|*" late-load")
                                /system/bin/echo "${'$'}args"
                                exit 0
                                ;;
                        esac
                    ;;
                esac
            done
            exit $LATE_LOAD_SCAN_CLEAR_CODE
        """.trimIndent()
        val command = "su -M -c ${shellQuote(scan)}"
        val result = runCommand(arrayOf("/system/bin/sh", "-c", command))
        return when (result.code) {
            0 -> true
            LATE_LOAD_SCAN_CLEAR_CODE -> false
            else -> error(
                "Unable to verify whether a KernelSU late-load is already running " +
                    "(rc=${result.code}): ${result.output}",
            )
        }
    }

    private fun shellQuote(value: String): String = "'${value.replace("'", "'\\''")}'"

    private suspend fun ensureShizukuShell() {
        require(ShizukuController.isRunning() || ShizukuController.pingUntilRunning()) {
            "Shizuku is not running"
        }
        require(ShizukuController.isGranted() || ShizukuController.requestPermission()) {
            "Shizuku permission was not granted"
        }
        val identity = ShizukuController.exec(arrayOf("/system/bin/id"))
        val output = identity.inputStream.bufferedReader().use { it.readText() } +
            identity.errorStream.bufferedReader().use { it.readText() }
        require(identity.waitFor() == 0 && output.contains("uid=2000(shell)")) {
            "Shizuku is not running as shell: ${output.trim()}"
        }
    }

    private fun shizukuStage(source: File, target: String, mode: String) {
        try {
            ShizukuController.writeFile(target, mode, source.inputStream())
        } catch (error: Throwable) {
            throw IllegalStateException(
                "Unable to stage $target through Shizuku: ${error.message}",
                error,
            )
        }
    }

    private fun storeVerifiedReceipt(modulesRequested: Boolean, modulesCompleted: Boolean) {
        val bootId = KernelSuDetector.bootId() ?: error("Unable to read boot_id")
        require(
            app.getSharedPreferences(RECEIPT, Application.MODE_PRIVATE)
                .edit()
                .putString(RECEIPT_BOOT_ID, bootId)
                .putBoolean(RECEIPT_VERIFIED, true)
                .putBoolean(RECEIPT_MODULES_REQUESTED, modulesRequested)
                .putBoolean(RECEIPT_MODULES_COMPLETED, modulesCompleted)
                .commit(),
        ) { "Unable to store KernelSU verification receipt" }
    }

    private fun storeModuleRequestReceipt() {
        val bootId = KernelSuDetector.bootId() ?: error("Unable to read boot_id")
        val alreadyVerified = verifiedThisBoot()
        require(
            app.getSharedPreferences(RECEIPT, Application.MODE_PRIVATE)
                .edit()
                .putString(RECEIPT_BOOT_ID, bootId)
                .putBoolean(RECEIPT_VERIFIED, alreadyVerified)
                .putBoolean(RECEIPT_MODULES_REQUESTED, true)
                .putBoolean(RECEIPT_MODULES_COMPLETED, false)
                .commit(),
        ) { "Unable to store module request receipt" }
    }

    private fun verifiedThisBoot(): Boolean {
        val bootId = KernelSuDetector.bootId() ?: return false
        val receipt = app.getSharedPreferences(RECEIPT, Application.MODE_PRIVATE)
        return receipt.getBoolean(RECEIPT_VERIFIED, false) &&
            receipt.getString(RECEIPT_BOOT_ID, null) == bootId
    }

    private fun modulesRequestedThisBoot(): Boolean {
        val bootId = KernelSuDetector.bootId() ?: return false
        val receipt = app.getSharedPreferences(RECEIPT, Application.MODE_PRIVATE)
        return receipt.getString(RECEIPT_BOOT_ID, null) == bootId &&
            receipt.getBoolean(RECEIPT_MODULES_REQUESTED, false)
    }

    private fun moduleStagesCompletedReceiptThisBoot(): Boolean {
        val bootId = KernelSuDetector.bootId() ?: return false
        val receipt = app.getSharedPreferences(RECEIPT, Application.MODE_PRIVATE)
        return receipt.getString(RECEIPT_BOOT_ID, null) == bootId &&
            receipt.getBoolean(RECEIPT_MODULES_COMPLETED, false)
    }

    private fun moduleMarkerMatchesBoot(): Boolean {
        val bootId = KernelSuDetector.bootId() ?: return false
        val localMarker = runCatching {
            File(SHIZUKU_MODULE_STATUS_PATH).readText(Charsets.US_ASCII).trim()
        }.getOrNull()
        if (localMarker == bootId) return true
        if (!ShizukuController.isRunning() || !ShizukuController.isGranted()) return false
        return runCatching {
            ShizukuController.capture(
                arrayOf("/system/bin/cat", SHIZUKU_MODULE_STATUS_PATH),
            ).trim() == bootId
        }.getOrDefault(false)
    }

    private suspend fun awaitModuleCompletionMarker(timeoutMillis: Long = 90_000): Boolean {
        val deadline = SystemClock.elapsedRealtime() + timeoutMillis
        while (SystemClock.elapsedRealtime() < deadline) {
            if (moduleMarkerMatchesBoot()) return true
            if (!ShizukuController.isRunning()) {
                ShizukuController.pingUntilRunning(500)
            }
            delay(250)
        }
        return moduleMarkerMatchesBoot()
    }

    private fun update(stage: RootStage, status: String) {
        mutableState.value = mutableState.value.copy(stage = stage, status = status, errorCode = null)
        appendLog("[*] $status")
    }

    private fun appendLog(line: String) {
        val clean = stripAnsi(line).trim()
        if (clean.isBlank()) return
        val full = (mutableState.value.fullLog + "\n" + clean).trim()
        mutableState.value = mutableState.value.copy(fullLog = full, visibleLog = sanitize(full))
    }

    private fun publishExploitLog(prefix: String, raw: String) {
        val full = listOf(prefix, stripAnsi(raw)).filter(String::isNotBlank).joinToString("\n")
        mutableState.value = mutableState.value.copy(fullLog = full, visibleLog = sanitize(full))
    }

    private fun recordFailure(error: Throwable) {
        val message = error.message ?: error.javaClass.simpleName
        val code = classifyFailure(message, mutableState.value.fullLog)
        appendLog("[-] $code: $message")
        val markerCompleted = moduleMarkerMatchesBoot()
        val activeAfterFailure = mutableState.value.kernelSuActive ||
            KernelSuDetector.active() || verifiedThisBoot() || markerCompleted
        mutableState.value = mutableState.value.copy(
            stage = RootStage.Failed,
            status = message,
            kernelSuActive = activeAfterFailure,
            modulesRequested = modulesRequestedThisBoot(),
            moduleStagesCompleted = moduleStagesCompletedReceiptThisBoot() || markerCompleted,
            errorCode = code,
        )
    }

    private fun classifyFailure(message: String, log: String): String {
        val exploitFailed = message.contains("Shizuku payload exited", true) ||
            message.contains("Temporary root", true) ||
            message.contains("exploit", true)
        val kernelSuLoadFailure = message.contains("no KernelSU driver", true) ||
            message.contains("KernelSU answered but reported itself incomplete", true) ||
            message.contains("could not stage ksud", true) ||
            message.contains("could not cover the loader path", true) ||
            message.contains("could not run the staged ksud", true) ||
            message.contains("ksud stopped", true)
        return when {
            message.contains("target", true) -> "TARGET_MISMATCH"
            exploitFailed && log.contains("kernel primitive became dirty", true) ->
                "KERNEL_PRIMITIVE_DIRTY"
            exploitFailed && log.contains("slide kaslr leak failed", true) ->
                "SLIDE_RESOLUTION_FAILED"
            exploitFailed && (
                log.contains("read_ok=0", true) || log.contains("write_ok=0", true)
            ) -> "KERNEL_PRIMITIVE_FAILED"
            exploitFailed && (
                message.contains("timeout", true) || log.contains(" timeout ", true)
            ) -> "EXPLOIT_TIMEOUT"
            exploitFailed && log.contains("done=0 root=0", true) ->
                "TEMPORARY_ROOT_FAILED"
            kernelSuLoadFailure -> "KERNELSU_LOAD_FAILED"
            message.contains("module stages", true) || message.contains("zygote restart", true) ||
                message.contains("Vector", true) ||
                message.contains("module completion marker", true) -> "MODULE_START_FAILED"
            message.contains("/data/local/tmp/ksud", true) ||
                message.contains("Staging KernelSU", true) -> "KERNELSU_STAGE_FAILED"
            message.contains("late-load", true) -> "KERNELSU_LOAD_FAILED"
            message.contains("KernelSU", true) -> "KERNELSU_VERIFICATION_FAILED"
            message.contains("extract", true) || message.contains("SHA-256", true) ||
                message.contains("Unable to stage", true) -> "PAYLOAD_PREP_FAILED"
            message.contains("Temporary root", true) -> "TEMPORARY_ROOT_FAILED"
            message.contains("Shizuku payload exited", true) -> "EXPLOIT_FAILED"
            message.contains("Shizuku", true) -> "SHIZUKU_FAILED"
            else -> "EXPLOIT_FAILED"
        }
    }

    companion object {
        private const val SHIZUKU_PAYLOAD_PATH = "/data/local/tmp/root-my-nothing-cve43499"
        private const val SHIZUKU_HELPER_PATH = "/data/local/tmp/cve-2026-43499-root"
        private const val SHIZUKU_KSUD_PATH = "/data/local/tmp/ksud"
        private const val SHIZUKU_KSUD_STAGE_PATH = "/data/local/tmp/.ksud-stage"
        private const val SHIZUKU_LOG_PATH = "/data/local/tmp/root-my-nothing-exploit.log"
        private const val SHIZUKU_MODULE_STATUS_PATH = "/data/local/tmp/.ksu-late-load-modules-ok"
        private const val SHIZUKU_EXPLOIT_COMMAND =
            "/system/bin/mkdir -p /data/local/tmp/asteroids; " +
                "(i=0; while [ \$i -lt 400 ]; do i=\$((i + 1)); " +
                "/system/bin/head -c 200000 /dev/urandom > /data/local/tmp/asteroids/.kick\$i 2>/dev/null; " +
                "/system/bin/sync; /system/bin/rm -f /data/local/tmp/asteroids/.kick\$i; done) & " +
                "kicker=\$!; $SHIZUKU_PAYLOAD_PATH > $SHIZUKU_LOG_PATH 2>&1; rc=\$?; " +
                "kill \$kicker 2>/dev/null; wait \$kicker 2>/dev/null; " +
                "/system/bin/rm -f /data/local/tmp/asteroids/.kick*; exit \$rc"
        private const val RECEIPT = "ksu_receipt"
        private const val RECEIPT_BOOT_ID = "boot_id"
        private const val RECEIPT_VERIFIED = "verified"
        private const val RECEIPT_MODULES_REQUESTED = "modules_requested"
        private const val RECEIPT_MODULES_COMPLETED = "modules_completed"
        private const val LATE_LOAD_SCAN_CLEAR_CODE = 42
        private const val SHELL_COMMAND_NOT_FOUND = 127
        private const val STREAM_READER_JOIN_MILLIS = 2_000L
        private val ANSI_ESCAPE = Regex("\u001B\\[[0-?]*[ -/]*[@-~]")
        private val KERNEL_POINTER = Regex("(?i)ffff(?:ff)?[0-9a-f]{10,12}")
        private val ROOT_IDENTITY = Regex("(?:^|\\s)uid=0(?:\\(|\\s|$)")

        private fun stripAnsi(value: String): String =
            ANSI_ESCAPE.replace(value, "").replace("\r", "")

        private fun sanitize(value: String): String = KERNEL_POINTER.replace(value, "<kernel-address>")
    }
}

private const val PREFERENCES_NAME = "root_my_nothing_preferences"
private const val COMPATIBILITY_CHECKS_KEY = "compatibility_checks_enabled"
