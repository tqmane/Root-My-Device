package dev.tqmane.rootmyonepluspad3

import android.app.Application
import android.os.SystemClock
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean

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
    RebootRequired,
    Failed,
}

data class RootUiState(
    val snapshot: DeviceSnapshot? = null,
    val compatibility: Compatibility = Compatibility(false, emptyList()),
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

internal fun classifyFailure(message: String, log: String): String {
    val diagnostic = "$message\n$log"
    return when {
        message.contains("reboot required", true) -> "REBOOT_REQUIRED"
        message.contains("target mismatch", true) -> "TARGET_MISMATCH"

        /* The exploit process normally reports only a non-zero Shizuku exit.
         * Prefer the exact UUID-oracle line captured in its log over that
         * wrapper error and over the many ordinary "slide pselect" lines. */
        diagnostic.contains("slide uuid preflight is stable", true) ->
            "SLIDE_UUID_ORACLE_DIRTY"
        diagnostic.contains("slide uuid read denied", true) ||
            diagnostic.contains("slide uuid read failed", true) ||
            diagnostic.contains("slide short uuid parse", true) ||
            diagnostic.contains("slide uuid preflight could not read", true) ->
            "SLIDE_UUID_READ_FAILED"
        diagnostic.contains("slide uuid still regenerates", true) ->
            "SLIDE_UUID_STORE_MISSED"
        diagnostic.contains("slide uuid collateral mismatch", true) ->
            "SLIDE_UUID_COLLATERAL_MISMATCH"
        diagnostic.contains("slide uuid direct-map echo", true) ->
            "SLIDE_UUID_DIRECT_MAP_ECHO"
        diagnostic.contains("slide uuid name pointer outside exact range", true) ->
            "SLIDE_UUID_NAME_POINTER_INVALID"
        diagnostic.contains("slide uuid derived base outside exact KASLR window", true) ||
            diagnostic.contains("slide child returned an implausible base", true) ->
            "SLIDE_UUID_BASE_INVALID"
        diagnostic.contains("slide store landed but exact base validation failed", true) ->
            "SLIDE_UUID_VALIDATION_FAILED"
        Regex("(?i)slide restore uuid[^\\n]*(stamped_exact=0|exact=0)")
            .containsMatchIn(diagnostic) -> "SLIDE_UUID_RESTORE_FAILED"
        diagnostic.contains("slide outcome is ambiguous after primitive entry", true) ->
            "SLIDE_OUTCOME_AMBIGUOUS"

        message.contains("extract", true) || message.contains("SHA-256", true) ->
            "PAYLOAD_PREP_FAILED"
        message.contains("timeout", true) || log.contains(" timeout", true) ->
            "EXPLOIT_TIMEOUT"
        message.contains("completion receipt", true) ||
            message.contains("completion marker", true) -> "COMPLETION_RECEIPT_MISSING"
        message.contains("manager", true) &&
            (message.contains("identity", true) ||
                message.contains("certificate", true)) -> "MANAGER_IDENTITY_MISMATCH"
        message.contains("mount namespace", true) ||
            message.contains("switch_mnt_ns", true) -> "MOUNT_NAMESPACE_FAILED"
        message.contains("zygote", true) || message.contains("system_server", true) ->
            "ZYGOTE_RESTART_FAILED"
        message.contains("NeoZygisk", true) -> "NEOZYGISK_VERIFICATION_FAILED"
        message.contains("Vector", true) -> "VECTOR_COMPATIBILITY_FAILED"
        message.contains("post-fs-data", true) || message.contains("module pre", true) ||
            message.contains("module stages", true) -> "MODULE_START_FAILED"
        message.contains("staging", true) -> "KERNELSU_STAGE_FAILED"
        message.contains("late-load", true) -> "KERNELSU_LOAD_FAILED"
        message.contains("KernelSU", true) -> "KERNELSU_VERIFICATION_FAILED"
        message.contains("Temporary root", true) -> "TEMPORARY_ROOT_FAILED"
        log.contains("stack", true) && log.contains("mismatch", true) ->
            "STACK_LAYOUT_MISMATCH"
        message.contains("Shizuku payload exited", true) &&
            (log.contains("pselect", true) || log.contains("cfi", true)) ->
            "PSELECT_STAGE_FAILED"
        message.contains("Shizuku payload exited", true) && log.contains("slide", true) ->
            "SLIDE_RESOLUTION_FAILED"
        message.contains("Shizuku payload exited", true) -> "EXPLOIT_FAILED"
        message.contains("Shizuku", true) -> "SHIZUKU_FAILED"
        log.contains("pselect", true) || log.contains("cfi", true) ->
            "PSELECT_STAGE_FAILED"
        log.contains("slide", true) -> "SLIDE_RESOLUTION_FAILED"
        log.contains("read_ok=0", true) || log.contains("write_ok=0", true) ||
            log.contains("kernel primitive", true) -> "KERNEL_PRIMITIVE_FAILED"
        else -> "EXPLOIT_FAILED"
    }
}

class RootViewModel(application: Application) : AndroidViewModel(application) {
    private val app = application
    private val rootLaunchClaimed = AtomicBoolean(false)
    private val mutableState = MutableStateFlow(RootUiState())
    val state: StateFlow<RootUiState> = mutableState.asStateFlow()

    init {
        refresh()
    }

    fun refresh() {
        if (mutableState.value.busy && mutableState.value.stage != RootStage.Checking) return
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val snapshot = DeviceSnapshot.current()
                val compatibility = OnePlusPad3Target.validate(snapshot)
                val kernelLive = kernelSuActive()
                val markerCompleted = kernelLive && moduleMarkerMatchesRequest()
                if (markerCompleted && !moduleStagesCompletedReceiptThisBoot()) {
                    storeVerifiedReceipt(modulesRequested = true, modulesCompleted = true)
                }
                /* A shell-readable completion marker is a recovery receipt, never
                 * evidence that the LKM itself is live.  Requiring /sys/module or
                 * /proc/modules prevents a stale/forged public marker from turning
                 * the UI green. */
                val active = kernelLive
                val modulesRequested = active && modulesRequestedThisBoot()
                val moduleStagesCompleted = active &&
                    (moduleStagesCompletedReceiptThisBoot() || markerCompleted)
                val interruptedRoot = compatibility.compatible && !active &&
                    rootOperationPendingThisBoot()
                val dirtyDecision = if (
                    compatibility.compatible && !active && !interruptedRoot &&
                    ShizukuController.isRunning() && ShizukuController.isGranted()
                ) {
                    dirtyMarkerDecision()
                } else {
                    DirtyMarkerDecision.Absent
                }
                val rebootRequired = interruptedRoot ||
                    dirtyDecision == DirtyMarkerDecision.CurrentBoot
                val unsafeMarker = dirtyDecision is DirtyMarkerDecision.Unsafe
                val log = buildString {
                    appendLine(
                        "[*] MODEL=${snapshot.model} DEVICE=${snapshot.device} " +
                            "PRODUCT=${snapshot.product}",
                    )
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
                        append("[+] exact OnePlus Pad 3 target matched")
                    } else {
                        compatibility.mismatches.forEach { appendLine("[-] $it") }
                    }
                    if (active) appendLine().append("[+] KernelSU is active")
                    if (moduleStagesCompleted) {
                        appendLine().append("[+] late-load module stages completed in this boot")
                    } else if (modulesRequested) {
                        appendLine().append(
                            "[!] late-load module stages requested but completion is unverified",
                        )
                    }
                    if (interruptedRoot) {
                        appendLine().append(
                            "[!] an interrupted root operation is pending in this boot",
                        )
                    } else if (dirtyDecision == DirtyMarkerDecision.CurrentBoot) {
                        appendLine().append("[!] kernel primitive dirty marker is current")
                    } else if (unsafeMarker) {
                        appendLine().append("[-] kernel primitive dirty marker is unsafe")
                    }
                }
                if (rootLaunchClaimed.get()) return@launch
                mutableState.value = RootUiState(
                    snapshot = snapshot,
                    compatibility = compatibility,
                    stage = when {
                        active -> RootStage.Success
                        rebootRequired -> RootStage.RebootRequired
                        compatibility.compatible && !unsafeMarker -> RootStage.Ready
                        else -> RootStage.Failed
                    },
                    status = when {
                        active && moduleStagesCompleted ->
                            "KernelSU active · module stages complete"
                        active && modulesRequested ->
                            "KernelSU active · module completion unverified"
                        active -> "KernelSU active"
                        rebootRequired -> "Interrupted kernel operation · reboot required"
                        unsafeMarker -> "Exploit dirty marker is unsafe"
                        compatibility.compatible -> "Ready"
                        else -> "Target mismatch"
                    },
                    kernelSuActive = active,
                    modulesRequested = modulesRequested,
                    moduleStagesCompleted = moduleStagesCompleted,
                    fullLog = log,
                    visibleLog = sanitize(log),
                    errorCode = when {
                        !compatibility.compatible -> "TARGET_MISMATCH"
                        rebootRequired -> "REBOOT_REQUIRED"
                        unsafeMarker -> "DIRTY_MARKER_UNSAFE"
                        else -> null
                    },
                )
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Throwable) {
                val message = error.message ?: error.javaClass.simpleName
                val log = "[-] REFRESH_FAILED: $message"
                if (!rootLaunchClaimed.get()) {
                    mutableState.value = mutableState.value.copy(
                        stage = RootStage.Failed,
                        status = message,
                        fullLog = log,
                        visibleLog = sanitize(log),
                        errorCode = "REFRESH_FAILED",
                    )
                }
            }
        }
    }

    fun startRoot() {
        val current = mutableState.value
        if (
            current.busy || current.kernelSuActive || !current.compatibility.compatible ||
            current.stage == RootStage.RebootRequired
        ) return
        if (!rootLaunchClaimed.compareAndSet(false, true)) return
        mutableState.value = current.copy(
            stage = RootStage.Extracting,
            status = "Connecting to Shizuku",
            errorCode = null,
        )
        viewModelScope.launch(Dispatchers.IO) {
            try {
                appendLog("[*] Connecting to Shizuku")
                ensureShizukuShell()
                appendLog("[+] Shizuku shell permission verified")
                require(!kernelSuActive()) {
                    "KernelSU became active before exploit launch; refresh instead"
                }
                ensureCleanExploitBoot()

                update(RootStage.Extracting, "Preparing verified native payloads")
                val artifacts = ArtifactStore.prepare(app, ::appendLog)
                storeRootOperationPending()

                update(RootStage.Exploiting, "Running CVE-2026-43499")
                runExploit(artifacts)
                update(RootStage.TemporaryRoot, "Temporary root acquired")
                appendLog("[+] temporary root markers verified")

                update(RootStage.LoadingKernelSu, "Staging KernelSU")
                stageKernelSu(artifacts)
                appendLog("[+] ksud staged at /data/local/tmp/ksud")

                update(RootStage.StartingModules, "Late-loading KernelSU with module stages")
                val runId = storeModuleRequestReceipt(artifacts.ksudSha256)
                val lateLoad = runHelper(
                    "--late-load",
                    OnePlusPad3Target.KMI,
                    OnePlusPad3Target.MANAGER_PACKAGE,
                    "modules",
                    "run-id=$runId",
                )
                if (lateLoad.output.isNotBlank()) appendLog(lateLoad.output)
                if (lateLoad.code != 0) {
                    error("KernelSU late-load/module stages failed (rc=${lateLoad.code}): ${lateLoad.output}")
                }
                require(awaitKernelSuActive()) {
                    "KernelSU live gate failed after successful late-load"
                }
                require(moduleMarkerMatchesRequest()) {
                    "KernelSU trusted completion receipt did not match this request"
                }
                storeVerifiedReceipt(modulesRequested = true, modulesCompleted = true)
                require(kernelSuActive()) {
                    "KernelSU disappeared after completion receipt verification"
                }

                appendLog("[+] KernelSU live gate and helper control receipt verified")
                appendLog("[+] late-load module stages completed; zygote boundary recreated")
                mutableState.value = mutableState.value.copy(
                    stage = RootStage.Success,
                    status = "KernelSU active · module stages complete",
                    kernelSuActive = true,
                    modulesRequested = true,
                    moduleStagesCompleted = true,
                    errorCode = null,
                )
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Throwable) {
                val message = error.message ?: error.javaClass.simpleName
                val dirtyDecision = runCatching { dirtyMarkerDecision() }.getOrNull()
                val activeAfterFailure = kernelSuActive()
                val operationPending = rootOperationPendingThisBoot()
                val cleanFailure = dirtyDecision == DirtyMarkerDecision.Absent
                val rebootRequired = message.startsWith("REBOOT_REQUIRED:") ||
                    dirtyDecision == DirtyMarkerDecision.CurrentBoot ||
                    (!activeAfterFailure && operationPending && !cleanFailure)
                if (!activeAfterFailure && operationPending && cleanFailure) {
                    runCatching { clearRootOperationPending() }
                }
                val code = if (rebootRequired) {
                    "REBOOT_REQUIRED"
                } else {
                    classifyFailure(message, mutableState.value.fullLog)
                }
                appendLog("[-] $code: $message")
                mutableState.value = mutableState.value.copy(
                    stage = if (rebootRequired) RootStage.RebootRequired else RootStage.Failed,
                    status = if (rebootRequired) {
                        "Kernel primitive entered · reboot required"
                    } else {
                        message
                    },
                    kernelSuActive = activeAfterFailure,
                    modulesRequested = modulesRequestedThisBoot(),
                    moduleStagesCompleted = activeAfterFailure &&
                        (moduleStagesCompletedReceiptThisBoot() || moduleMarkerMatchesRequest()),
                    errorCode = code,
                )
            } finally {
                rootLaunchClaimed.set(false)
            }
        }
    }

    private suspend fun runExploit(artifacts: RuntimeArtifacts) {
        shizukuStage(artifacts.helper, SHIZUKU_HELPER_PATH, "755")
        shizukuStage(artifacts.payload, SHIZUKU_PAYLOAD_PATH, "755")
        appendLog("[+] standalone payload staged through Shizuku")

        val prefix = mutableState.value.fullLog
        val started = SystemClock.elapsedRealtime()
        val cleanup = ShizukuController.waitAndCapture(
            ShizukuController.exec(
                arrayOf("/system/bin/rm", "-f", SHIZUKU_LOG_PATH),
            ),
        )
        require(cleanup.exitCode == 0) {
            "Unable to reset exploit log: ${(cleanup.stdout + cleanup.stderr).trim()}"
        }
        val process = ShizukuController.exec(
            arrayOf("/system/bin/sh", "-c", SHIZUKU_EXPLOIT_COMMAND),
            emptyArray(),
            "/data/local/tmp",
        )

        val outcome = awaitExploitProcessOutcome(
            process = process,
            readLog = {
                ShizukuController.capture(
                    arrayOf("/system/bin/cat", SHIZUKU_LOG_PATH),
                )
            },
            onLogChanged = { raw -> publishExploitLog(prefix, raw) },
            pollDelay = {
                val elapsedMinutes =
                    (SystemClock.elapsedRealtime() - started) / 60_000
                if (elapsedMinutes > 0 && elapsedMinutes % 5L == 0L) {
                    mutableState.value = mutableState.value.copy(
                        status = "Shizuku exploit running (${elapsedMinutes} min)",
                    )
                }
                delay(250)
            },
        )
        if (outcome is ExploitProcessOutcome.TrustedSuccess) {
            /* Do not destroy this exact supervisor process. Its successful
             * attempt may have installed helper/watchdog descendants, and the
             * permissive watchdog window is now running. Continue directly to
             * staging and the helper contract without waiting for output EOF. */
            appendLog("[+] trusted exploit success handshake received; continuing without stdout EOF")
            return
        }
        if (outcome is ExploitProcessOutcome.RebootRequired) {
            error(
                "REBOOT_REQUIRED: native supervisor retained a current-boot " +
                    "dirty attempt; process left untouched",
            )
        }

        val code = process.waitFor()
        val raw = ShizukuController.capture(
            arrayOf("/system/bin/cat", SHIZUKU_LOG_PATH),
        )
        publishExploitLog(prefix, raw)
        require(code == 0) { "Shizuku payload exited $code" }
        val receipts = normalizeExploitReceiptLog(raw)
        require(ROOT_INSTALL_SUCCESS_LINE.containsMatchIn(receipts)) {
            "Temporary root success marker missing"
        }
        require(EXPLOIT_COMPLETION_LINE.containsMatchIn(receipts)) {
            "Exact exploit completion marker missing"
        }
    }

    private fun ensureCleanExploitBoot() {
        when (val decision = dirtyMarkerDecision()) {
            DirtyMarkerDecision.Absent -> Unit
            DirtyMarkerDecision.CurrentBoot -> error(
                "REBOOT_REQUIRED: the kernel primitive was already entered in this boot",
            )
            is DirtyMarkerDecision.Unsafe -> error(
                "Exploit dirty marker is unsafe: ${decision.reason}",
            )
        }
    }

    private fun dirtyMarkerDecision(): DirtyMarkerDecision {
        if (!ShizukuController.isRunning() || !ShizukuController.isGranted()) {
            return DirtyMarkerDecision.Unsafe("Shizuku is unavailable")
        }
        val bootId = KernelSuDetector.bootId()
            ?: return DirtyMarkerDecision.Unsafe("boot_id is unreadable")
        val procStat = ShizukuController.capture(
            arrayOf("/system/bin/cat", "/proc/stat"),
        )
        val btime = ExploitRetryGuard.parseBtime(procStat)
            ?: return DirtyMarkerDecision.Unsafe("kernel btime is unreadable")
        val markerPath = "$DIRTY_MARKER_PATH_PREFIX.$btime"
        val probe = ShizukuController.capture(
            arrayOf("/system/bin/sh", "-c", dirtyMarkerProbeCommand(markerPath)),
        )
        return ExploitRetryGuard.evaluate(probe, bootId, btime)
    }

    private suspend fun stageKernelSu(artifacts: RuntimeArtifacts) {
        shizukuStage(artifacts.ksud, SHIZUKU_KSUD_PATH, "755")
    }

    private suspend fun runHelper(vararg arguments: String): CommandResult {
        val process = ShizukuController.exec(arrayOf(SHIZUKU_HELPER_PATH) + arguments)
        val captured = ShizukuController.waitAndCapture(process)
        return CommandResult(
            captured.exitCode,
            stripAnsi(captured.stdout + captured.stderr).trim(),
        )
    }

    private suspend fun ensureShizukuShell() {
        require(ShizukuController.isRunning() || ShizukuController.pingUntilRunning()) {
            "Shizuku is not running"
        }
        require(ShizukuController.isGranted() || ShizukuController.requestPermission()) {
            "Shizuku permission was not granted"
        }
        val identity = ShizukuController.exec(arrayOf("/system/bin/id"))
        val captured = ShizukuController.waitAndCapture(identity)
        val output = captured.stdout + captured.stderr
        require(captured.exitCode == 0 && output.contains("uid=2000(shell)")) {
            "Shizuku is not running as shell: ${output.trim()}"
        }
    }

    private suspend fun awaitKernelSuActive(timeoutMillis: Long = 10_000): Boolean {
        val deadline = SystemClock.elapsedRealtime() + timeoutMillis
        while (SystemClock.elapsedRealtime() < deadline) {
            if (kernelSuActive()) return true
            delay(100)
        }
        return kernelSuActive()
    }

    private fun kernelSuActive(): Boolean {
        val directActive = KernelSuDetector.active()
        if (directActive) return true

        val shizukuRunning = ShizukuController.isRunning()
        val shizukuGranted = shizukuRunning && ShizukuController.isGranted()
        val procModules = if (shizukuGranted) {
            runCatching {
                ShizukuController.capture(
                    arrayOf("/system/bin/cat", "/proc/modules"),
                )
            }.getOrNull()
        } else {
            null
        }
        return KernelSuLiveGate.active(
            directActive = directActive,
            shizukuRunning = shizukuRunning,
            shizukuGranted = shizukuGranted,
            procModules = procModules,
        )
    }

    private suspend fun shizukuStage(source: File, target: String, mode: String) {
        try {
            ShizukuController.writeFile(target, mode, source.inputStream())
            val digest = MessageDigest.getInstance("SHA-256")
            source.inputStream().use { input ->
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                while (true) {
                    val count = input.read(buffer)
                    if (count <= 0) break
                    digest.update(buffer, 0, count)
                }
            }
            val expected = digest.digest().joinToString("") { "%02x".format(it) }
            val verify = ShizukuController.exec(arrayOf("/system/bin/sha256sum", target))
            val captured = ShizukuController.waitAndCapture(verify)
            val output = captured.stdout + captured.stderr
            val actual = output.trim().substringBefore(' ')
            check(captured.exitCode == 0 && actual == expected) {
                "Remote SHA-256 mismatch for $target"
            }
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
                .putString(RECEIPT_TARGET_ID, OnePlusPad3Target.ID)
                .putLong(RECEIPT_TIMESTAMP, System.currentTimeMillis())
                .putBoolean(RECEIPT_VERIFIED, true)
                .putBoolean(RECEIPT_MODULES_REQUESTED, modulesRequested)
                .putBoolean(RECEIPT_MODULES_COMPLETED, modulesCompleted)
                .putBoolean(RECEIPT_OPERATION_PENDING, false)
                .commit(),
        ) { "Unable to store KernelSU verification receipt" }
    }

    private fun storeRootOperationPending() {
        val bootId = KernelSuDetector.bootId() ?: error("Unable to read boot_id")
        require(
            app.getSharedPreferences(RECEIPT, Application.MODE_PRIVATE)
                .edit()
                .putString(RECEIPT_BOOT_ID, bootId)
                .putString(RECEIPT_TARGET_ID, OnePlusPad3Target.ID)
                .putLong(RECEIPT_TIMESTAMP, System.currentTimeMillis())
                .putBoolean(RECEIPT_VERIFIED, false)
                .putBoolean(RECEIPT_MODULES_REQUESTED, false)
                .putBoolean(RECEIPT_MODULES_COMPLETED, false)
                .putBoolean(RECEIPT_OPERATION_PENDING, true)
                .remove(RECEIPT_RUN_ID)
                .remove(RECEIPT_KSUD_SHA256)
                .commit(),
        ) { "Unable to store pending root-operation receipt" }
    }

    private fun storeModuleRequestReceipt(ksudSha256: String): String {
        val bootId = KernelSuDetector.bootId() ?: error("Unable to read boot_id")
        require(ModuleCompletionReceipt.isSha256(ksudSha256)) { "Invalid pinned ksud SHA-256" }
        val nonce = ByteArray(16).also(SecureRandom()::nextBytes)
            .joinToString("") { "%02x".format(it) }
        require(
            app.getSharedPreferences(RECEIPT, Application.MODE_PRIVATE)
                .edit()
                .putString(RECEIPT_BOOT_ID, bootId)
                .putString(RECEIPT_TARGET_ID, OnePlusPad3Target.ID)
                .putLong(RECEIPT_TIMESTAMP, System.currentTimeMillis())
                .putBoolean(RECEIPT_VERIFIED, false)
                .putBoolean(RECEIPT_MODULES_REQUESTED, true)
                .putBoolean(RECEIPT_MODULES_COMPLETED, false)
                .putBoolean(RECEIPT_OPERATION_PENDING, true)
                .putString(RECEIPT_RUN_ID, nonce)
                .putString(RECEIPT_KSUD_SHA256, ksudSha256)
                .commit(),
        ) { "Unable to store module request receipt" }
        return nonce
    }

    private fun modulesRequestedThisBoot(): Boolean {
        val bootId = KernelSuDetector.bootId() ?: return false
        val receipt = app.getSharedPreferences(RECEIPT, Application.MODE_PRIVATE)
        return receiptMatches(receipt, bootId) &&
            receipt.getBoolean(RECEIPT_MODULES_REQUESTED, false)
    }

    private fun moduleStagesCompletedReceiptThisBoot(): Boolean {
        val bootId = KernelSuDetector.bootId() ?: return false
        val receipt = app.getSharedPreferences(RECEIPT, Application.MODE_PRIVATE)
        return receiptMatches(receipt, bootId) &&
            receipt.getBoolean(RECEIPT_VERIFIED, false) &&
            receipt.getBoolean(RECEIPT_MODULES_COMPLETED, false)
    }

    private fun rootOperationPendingThisBoot(): Boolean {
        val bootId = KernelSuDetector.bootId() ?: return false
        val receipt = app.getSharedPreferences(RECEIPT, Application.MODE_PRIVATE)
        return receiptMatches(receipt, bootId) &&
            receipt.getBoolean(RECEIPT_OPERATION_PENDING, false)
    }

    private fun clearRootOperationPending() {
        require(
            app.getSharedPreferences(RECEIPT, Application.MODE_PRIVATE)
                .edit()
                .putBoolean(RECEIPT_OPERATION_PENDING, false)
                .commit(),
        ) { "Unable to clear pending root-operation receipt" }
    }

    private fun receiptMatches(receipt: android.content.SharedPreferences, bootId: String): Boolean =
        receipt.getString(RECEIPT_BOOT_ID, null) == bootId &&
            receipt.getString(RECEIPT_TARGET_ID, null) == OnePlusPad3Target.ID &&
            receipt.getLong(RECEIPT_TIMESTAMP, 0L) > 0L

    private fun moduleMarkerMatchesRequest(): Boolean {
        val bootId = KernelSuDetector.bootId() ?: return false
        if (!ShizukuController.isRunning() || !ShizukuController.isGranted()) return false
        val receipt = app.getSharedPreferences(RECEIPT, Application.MODE_PRIVATE)
        if (!receiptMatches(receipt, bootId)) return false
        val runId = receipt.getString(RECEIPT_RUN_ID, null) ?: return false
        val ksudSha256 = receipt.getString(RECEIPT_KSUD_SHA256, null) ?: return false
        return runCatching {
            val probe = ShizukuController.capture(
                arrayOf("/system/bin/sh", "-c", MODULE_STATUS_PROBE_COMMAND),
            )
            ModuleCompletionReceipt.matches(probe, bootId, runId, ksudSha256)
        }.getOrDefault(false)
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

    companion object {
        private const val SHIZUKU_PAYLOAD_PATH =
            "/data/local/tmp/root-my-oneplus-pad3-cve43499"
        private const val SHIZUKU_HELPER_PATH = "/data/local/tmp/cve-2026-43499-root"
        private const val SHIZUKU_KSUD_PATH = "/data/local/tmp/ksud"
        private const val SHIZUKU_LOG_PATH =
            "/data/local/tmp/root-my-oneplus-pad3-exploit.log"
        private val MODULE_STATUS_PROBE_COMMAND = ModuleCompletionReceipt.probeCommand()
        private const val DIRTY_MARKER_PATH_PREFIX =
            "/data/local/tmp/.oneplus-pad3-exploit-dirty"

        private fun dirtyMarkerProbeCommand(markerPath: String): String =
            "if [ -L '$markerPath' ]; then " +
                "echo '${ExploitRetryGuard.PROBE_UNSAFE}'; " +
                "elif [ ! -e '$markerPath' ]; then " +
                "echo '${ExploitRetryGuard.PROBE_ABSENT}'; " +
                "elif exec 3< '$markerPath'; then " +
                "echo '${ExploitRetryGuard.PROBE_REGULAR}'; " +
                "/system/bin/stat -L -c 'uid=%u gid=%g mode=%a nlink=%h' " +
                "\"/proc/\$\$/fd/3\" || exit 1; " +
                "/system/bin/cat <&3; " +
                "else echo '${ExploitRetryGuard.PROBE_UNSAFE}'; fi"
        private const val SHIZUKU_EXPLOIT_COMMAND =
            "exec $SHIZUKU_PAYLOAD_PATH > $SHIZUKU_LOG_PATH 2>&1"
        private const val RECEIPT = "oneplus_pad3_ksu_receipt"
        private const val RECEIPT_BOOT_ID = "boot_id"
        private const val RECEIPT_TARGET_ID = "target_id"
        private const val RECEIPT_TIMESTAMP = "timestamp"
        private const val RECEIPT_VERIFIED = "verified"
        private const val RECEIPT_MODULES_REQUESTED = "modules_requested"
        private const val RECEIPT_MODULES_COMPLETED = "modules_completed"
        private const val RECEIPT_RUN_ID = "run_id"
        private const val RECEIPT_KSUD_SHA256 = "ksud_sha256"
        private const val RECEIPT_OPERATION_PENDING = "operation_pending"
        private val ANSI_ESCAPE = Regex("\u001B\\[[0-?]*[ -/]*[@-~]")
        private val KERNEL_POINTER = Regex("(?i)ffff(?:ff)?[0-9a-f]{10,12}")

        private fun stripAnsi(value: String): String =
            ANSI_ESCAPE.replace(value, "").replace("\r", "")

        private fun sanitize(value: String): String = KERNEL_POINTER.replace(value, "<kernel-address>")
    }
}
