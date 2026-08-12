package dev.tqmane.rootmynothing

import android.content.pm.PackageManager
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import kotlinx.coroutines.delay
import kotlinx.coroutines.suspendCancellableCoroutine
import moe.shizuku.server.IRemoteProcess
import moe.shizuku.server.IShizukuService
import rikka.shizuku.Shizuku
import java.io.InputStream
import java.io.OutputStream
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.concurrent.thread

object ShizukuController {
    private const val PERMISSION_REQUEST_CODE = 0x524d

    fun isRunning(): Boolean = runCatching { Shizuku.pingBinder() }.getOrDefault(false)

    suspend fun pingUntilRunning(timeoutMillis: Long = 5_000): Boolean {
        val deadline = SystemClock.elapsedRealtime() + timeoutMillis
        while (SystemClock.elapsedRealtime() < deadline) {
            if (isRunning()) return true
            delay(100)
        }
        return isRunning()
    }

    fun isGranted(): Boolean = runCatching {
        isRunning() && Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED
    }.getOrDefault(false)

    suspend fun requestPermission(): Boolean {
        if (isGranted()) return true
        if (!isRunning()) return false
        return suspendCancellableCoroutine { continuation ->
            lateinit var listener: Shizuku.OnRequestPermissionResultListener
            listener = Shizuku.OnRequestPermissionResultListener { requestCode, result ->
                if (requestCode == PERMISSION_REQUEST_CODE) {
                    Shizuku.removeRequestPermissionResultListener(listener)
                    if (continuation.isActive) {
                        continuation.resume(result == PackageManager.PERMISSION_GRANTED)
                    }
                }
            }
            Shizuku.addRequestPermissionResultListener(listener)
            continuation.invokeOnCancellation {
                Shizuku.removeRequestPermissionResultListener(listener)
            }
            runCatching { Shizuku.requestPermission(PERMISSION_REQUEST_CODE) }
                .onFailure { error ->
                    Shizuku.removeRequestPermissionResultListener(listener)
                    if (continuation.isActive) continuation.resumeWithException(error)
                }
        }
    }

    fun exec(
        command: Array<String>,
        environment: Array<String>? = null,
        directory: String? = null,
    ): Process {
        val binder = Shizuku.getBinder() ?: error("Shizuku binder is not available")
        val service = IShizukuService.Stub.asInterface(binder)
        return RemoteProcess(service.newProcess(command, environment, directory))
    }

    fun writeFile(remotePath: String, mode: String, source: InputStream) {
        require(mode.matches(Regex("[0-7]{3,4}"))) { "Invalid file mode: $mode" }
        val quoted = shellQuote(remotePath)
        val command = """
            target=$quoted
            umask 077
            tmp=${'$'}(/system/bin/mktemp "${'$'}target.rmn-tmp.XXXXXX") || exit ${'$'}?
            cleanup() { /system/bin/rm -f "${'$'}tmp"; }
            trap cleanup EXIT HUP INT TERM
            /system/bin/cat > "${'$'}tmp" &&
                /system/bin/chmod $mode "${'$'}tmp" &&
                /system/bin/mv -f "${'$'}tmp" "${'$'}target"
        """.trimIndent()
        val process = exec(
            arrayOf("/system/bin/sh", "-c", command),
        )
        var stderr = ""
        val stderrReader = thread(isDaemon = true, name = "shizuku-stage-stderr") {
            stderr = runCatching {
                process.errorStream.bufferedReader().use { it.readText() }
            }.getOrDefault("")
        }
        var copyFailure: Throwable? = null
        val exitCode = try {
            try {
                process.outputStream.use { output -> source.use { it.copyTo(output) } }
            } catch (error: Throwable) {
                copyFailure = error
            }
            process.waitFor()
        } finally {
            runCatching { if (process.isAlive) process.destroy() }
            runCatching { stderrReader.join(STREAM_READER_JOIN_MILLIS) }
        }
        check(exitCode == 0 && copyFailure == null) {
            buildString {
                append("Failed to stage $remotePath (exit $exitCode)")
                copyFailure?.message?.takeIf(String::isNotBlank)?.let { append(": $it") }
                stderr.trim().takeIf(String::isNotBlank)?.let { append("; stderr: $it") }
            }
        }
    }

    fun capture(command: Array<String>): String {
        val process = exec(command)
        var stdout = ""
        var stderr = ""
        val stdoutReader = thread(isDaemon = true, name = "shizuku-capture-stdout") {
            stdout = runCatching {
                process.inputStream.bufferedReader().use { it.readText() }
            }.getOrDefault("")
        }
        val stderrReader = thread(isDaemon = true, name = "shizuku-capture-stderr") {
            stderr = runCatching {
                process.errorStream.bufferedReader().use { it.readText() }
            }.getOrDefault("")
        }
        return try {
            val exitCode = process.waitFor()
            stdoutReader.join()
            stderrReader.join()
            if (exitCode == 0) stdout + stderr else ""
        } finally {
            runCatching { if (process.isAlive) process.destroy() }
            runCatching { stdoutReader.join(STREAM_READER_JOIN_MILLIS) }
            runCatching { stderrReader.join(STREAM_READER_JOIN_MILLIS) }
        }
    }

    private fun shellQuote(value: String): String = "'${value.replace("'", "'\\''")}'"

    private const val STREAM_READER_JOIN_MILLIS = 2_000L

    private class RemoteProcess(private val remote: IRemoteProcess) : Process() {
        private val stdout by lazy {
            ParcelFileDescriptor.AutoCloseInputStream(remote.inputStream)
        }
        private val stdin by lazy {
            ParcelFileDescriptor.AutoCloseOutputStream(remote.outputStream)
        }
        private val stderr by lazy {
            ParcelFileDescriptor.AutoCloseInputStream(remote.errorStream)
        }

        override fun getInputStream(): InputStream = stdout
        override fun getOutputStream(): OutputStream = stdin
        override fun getErrorStream(): InputStream = stderr
        override fun waitFor(): Int = remote.waitFor()
        override fun exitValue(): Int = remote.exitValue()
        override fun isAlive(): Boolean = remote.alive()
        override fun destroy() = runCatching { remote.destroy() }.let { Unit }
        override fun destroyForcibly(): Process = apply { destroy() }
    }
}
