package dev.tqmane.rootmyonepluspad3

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.tqmane.rootmyonepluspad3.ui.RootMyOnePlusPad3Theme

private enum class AppTab(val icon: ImageVector) {
    Home(Icons.Default.Home),
    Logs(Icons.Default.Description),
    About(Icons.Default.Info),
}

class MainActivity : ComponentActivity() {
    private val viewModel: RootViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            RootMyOnePlusPad3Theme {
                val state by viewModel.state.collectAsStateWithLifecycle()
                LaunchedEffect(state.busy) {
                    if (state.busy) {
                        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
                    } else {
                        window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
                    }
                }
                RootMyOnePlusPad3App(
                    state = state,
                    onRoot = viewModel::startRoot,
                    onRefresh = viewModel::refresh,
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun RootMyOnePlusPad3App(
    state: RootUiState,
    onRoot: () -> Unit,
    onRefresh: () -> Unit,
) {
    var tab by remember { mutableStateOf(AppTab.Home) }
    val context = LocalContext.current
    val export = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain"),
    ) { uri ->
        if (uri != null) {
            runCatching {
                context.contentResolver.openOutputStream(uri)?.use {
                    it.write(state.fullLog.toByteArray())
                } ?: error("Unable to open destination")
            }.onSuccess {
                Toast.makeText(context, R.string.logs_exported, Toast.LENGTH_SHORT).show()
            }.onFailure {
                Toast.makeText(context, it.message, Toast.LENGTH_LONG).show()
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(stringResource(R.string.app_name), fontWeight = FontWeight.SemiBold)
                        Text(
                            stringResource(R.string.target_exact),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                },
                actions = {
                    OutlinedButton(
                        onClick = onRefresh,
                        enabled = !state.busy,
                        contentPadding = PaddingValues(horizontal = 12.dp),
                    ) {
                        Icon(Icons.Default.Refresh, null, Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp))
                        Text(stringResource(R.string.refresh))
                    }
                },
            )
        },
        bottomBar = {
            NavigationBar {
                AppTab.entries.forEach { item ->
                    NavigationBarItem(
                        selected = tab == item,
                        onClick = { tab = item },
                        icon = { Icon(item.icon, null) },
                        label = {
                            Text(
                                when (item) {
                                    AppTab.Home -> stringResource(R.string.home)
                                    AppTab.Logs -> stringResource(R.string.logs)
                                    AppTab.About -> stringResource(R.string.about)
                                },
                            )
                        },
                    )
                }
            }
        },
    ) { padding ->
        when (tab) {
            AppTab.Home -> HomeScreen(
                state,
                onRoot,
                onRefresh,
                Modifier.padding(padding),
            )
            AppTab.Logs -> LogsScreen(
                state,
                onCopy = {
                    val clipboard = context.getSystemService(ClipboardManager::class.java)
                    clipboard.setPrimaryClip(
                        ClipData.newPlainText("Root My OnePlus Pad 3 log", state.fullLog),
                    )
                    Toast.makeText(context, R.string.logs_copied, Toast.LENGTH_SHORT).show()
                },
                onExport = {
                    export.launch(
                        "root-my-oneplus-pad3-${KernelSuDetector.bootId() ?: "log"}.txt",
                    )
                },
                modifier = Modifier.padding(padding),
            )
            AppTab.About -> AboutScreen(Modifier.padding(padding))
        }
    }
}

@Composable
private fun HomeScreen(
    state: RootUiState,
    onRoot: () -> Unit,
    onRefresh: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        StatusHero(state)
        DeviceCard(state)
        ProgressCard(state)

        if (!state.compatibility.compatible) {
            NoticeCard(
                icon = Icons.Default.Error,
                title = stringResource(R.string.not_compatible),
                body = state.compatibility.mismatches.joinToString("\n"),
                error = true,
            )
        } else if (!state.kernelSuActive) {
            NoticeCard(
                icon = Icons.Default.Warning,
                title = stringResource(R.string.warning),
                body = stringResource(R.string.target_guard),
                error = false,
            )
        }

        Button(
            onClick = {
                if (state.kernelSuActive) openManager(context) else onRoot()
            },
            enabled = state.kernelSuActive ||
                (state.compatibility.compatible && !state.busy &&
                    state.stage != RootStage.RebootRequired),
            modifier = Modifier.fillMaxWidth().height(56.dp),
        ) {
            if (state.busy) {
                CircularProgressIndicator(
                    modifier = Modifier.size(22.dp),
                    strokeWidth = 2.dp,
                    color = MaterialTheme.colorScheme.onPrimary,
                )
                Spacer(Modifier.width(10.dp))
                Text(state.status, maxLines = 1, overflow = TextOverflow.Ellipsis)
            } else {
                Icon(
                    if (state.kernelSuActive) Icons.AutoMirrored.Filled.OpenInNew else Icons.Default.Key,
                    null,
                )
                Spacer(Modifier.width(10.dp))
                Text(
                    if (state.kernelSuActive) {
                        stringResource(R.string.open_manager)
                    } else if (state.stage == RootStage.Failed && state.compatibility.compatible) {
                        stringResource(R.string.retry)
                    } else if (state.stage == RootStage.RebootRequired) {
                        stringResource(R.string.reboot_required)
                    } else {
                        stringResource(R.string.root)
                    },
                )
            }
        }

        if (state.kernelSuActive && !managerInstalled(context)) {
            OutlinedButton(
                onClick = { openManager(context) },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Icon(Icons.Default.FileDownload, null)
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.install_manager))
            }
        }

        if (state.kernelSuActive && !state.modulesRequested) {
            NoticeCard(
                icon = Icons.Default.Warning,
                title = stringResource(R.string.warning),
                body = stringResource(R.string.modules_reboot_required),
                error = false,
            )
        } else if (state.kernelSuActive && !state.moduleStagesCompleted) {
            NoticeCard(
                icon = Icons.Default.Warning,
                title = stringResource(R.string.warning),
                body = stringResource(R.string.modules_completion_unverified),
                error = false,
            )
        }

        if (state.stage == RootStage.RebootRequired) {
            NoticeCard(
                icon = Icons.Default.Warning,
                title = stringResource(R.string.reboot_required),
                body = stringResource(R.string.exploit_reboot_required),
                error = true,
            )
        }

        if (state.stage == RootStage.Failed && state.compatibility.compatible) {
            OutlinedButton(onClick = onRefresh, modifier = Modifier.fillMaxWidth()) {
                Text("${state.errorCode ?: "FAILED"}: ${state.status}")
            }
        }
    }
}

@Composable
private fun StatusHero(state: RootUiState) {
    val success = state.kernelSuActive
    val color = when {
        success -> Color(0xFF2E7D32)
        state.stage == RootStage.Failed || state.stage == RootStage.RebootRequired ->
            MaterialTheme.colorScheme.error
        else -> MaterialTheme.colorScheme.primary
    }
    Card(
        colors = CardDefaults.cardColors(containerColor = color),
        shape = RoundedCornerShape(28.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier.padding(22.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                if (success) Icons.Default.CheckCircle else Icons.Default.Security,
                null,
                tint = Color.White,
                modifier = Modifier.size(46.dp),
            )
            Spacer(Modifier.width(16.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    if (success) stringResource(R.string.active) else state.status,
                    color = Color.White,
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    if (success && state.moduleStagesCompleted) {
                        "KernelSU 32601 · module stages complete"
                    } else if (success && state.modulesRequested) {
                        "KernelSU 32601 · module completion unverified"
                    } else if (success) {
                        "KernelSU 32601 · UAPI 2 · late-load"
                    } else {
                        "CVE-2026-43499 · temporary root"
                    },
                    color = Color.White.copy(alpha = 0.82f),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
    }
}

@Composable
private fun DeviceCard(state: RootUiState) {
    val snapshot = state.snapshot ?: return
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(11.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.PhoneAndroid, null)
                Spacer(Modifier.width(10.dp))
                Text(stringResource(R.string.device_compatibility), fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.weight(1f))
                Text(
                    if (state.compatibility.compatible) {
                        stringResource(R.string.compatible)
                    } else {
                        stringResource(R.string.not_compatible)
                    },
                    color = if (state.compatibility.compatible) Color(0xFF2E7D32) else MaterialTheme.colorScheme.error,
                    fontWeight = FontWeight.Bold,
                )
            }
            HorizontalDivider()
            DetailRow(stringResource(R.string.device), "${snapshot.model} / ${snapshot.device}")
            DetailRow(stringResource(R.string.product), snapshot.product)
            DetailRow(stringResource(R.string.build), snapshot.display)
            DetailRow(stringResource(R.string.sdk), snapshot.sdk.toString())
            DetailRow(stringResource(R.string.security_patch), snapshot.securityPatch)
            DetailRow(stringResource(R.string.kernel), snapshot.kernelRelease)
            DetailRow(stringResource(R.string.page_size), "${snapshot.pageSize} bytes")
        }
    }
}

@Composable
private fun DetailRow(label: String, value: String) {
    Column {
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun ProgressCard(state: RootUiState) {
    val steps = listOf(
        RootStage.Checking to "Target validation",
        RootStage.Extracting to "Payload verification",
        RootStage.Exploiting to "Temporary root",
        RootStage.LoadingKernelSu to "KernelSU late-load",
        RootStage.Verifying to "Control verification",
        RootStage.StartingModules to "Module stages",
    )
    val stageOrder = mapOf(
        RootStage.Checking to 0,
        RootStage.Ready to 1,
        RootStage.Extracting to 1,
        RootStage.Exploiting to 2,
        RootStage.TemporaryRoot to 3,
        RootStage.LoadingKernelSu to 3,
        RootStage.Verifying to 4,
        RootStage.StartingModules to 5,
        RootStage.Success to 6,
        RootStage.RebootRequired to -1,
        RootStage.Failed to -1,
    )
    val current = stageOrder[state.stage] ?: 0
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.BugReport, null)
                Spacer(Modifier.width(10.dp))
                Text(stringResource(R.string.exploit_status), fontWeight = FontWeight.SemiBold)
            }
            if (state.busy) LinearProgressIndicator(Modifier.fillMaxWidth())
            steps.forEachIndexed { index, (_, label) ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    val done = state.stage == RootStage.Success || (current > index && current >= 0)
                    val active = state.busy && current == index
                    Icon(
                        when {
                            done -> Icons.Default.CheckCircle
                            active -> Icons.Default.Memory
                            else -> Icons.Default.Security
                        },
                        null,
                        tint = when {
                            done -> Color(0xFF2E7D32)
                            active -> MaterialTheme.colorScheme.primary
                            else -> MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
                        },
                        modifier = Modifier.size(20.dp),
                    )
                    Spacer(Modifier.width(10.dp))
                    Text(label, style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
    }
}

@Composable
private fun NoticeCard(icon: ImageVector, title: String, body: String, error: Boolean) {
    val container = if (error) {
        MaterialTheme.colorScheme.errorContainer
    } else {
        MaterialTheme.colorScheme.tertiaryContainer
    }
    Card(colors = CardDefaults.cardColors(containerColor = container), modifier = Modifier.fillMaxWidth()) {
        Row(Modifier.padding(16.dp)) {
            Icon(icon, null)
            Spacer(Modifier.width(12.dp))
            Column {
                Text(title, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(4.dp))
                Text(body, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
private fun LogsScreen(
    state: RootUiState,
    onCopy: () -> Unit,
    onExport: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            OutlinedButton(onClick = onCopy, enabled = state.fullLog.isNotBlank()) {
                Icon(Icons.Default.ContentCopy, null)
                Spacer(Modifier.width(7.dp))
                Text(stringResource(R.string.copy_logs))
            }
            OutlinedButton(onClick = onExport, enabled = state.fullLog.isNotBlank()) {
                Icon(Icons.Default.FileDownload, null)
                Spacer(Modifier.width(7.dp))
                Text(stringResource(R.string.export_logs))
            }
        }
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(
                    MaterialTheme.colorScheme.surfaceContainer,
                    RoundedCornerShape(18.dp),
                )
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
        ) {
            Text(
                state.visibleLog.ifBlank { stringResource(R.string.no_logs) },
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

@Composable
private fun AboutScreen(modifier: Modifier = Modifier) {
    Column(
        modifier = modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Icon(Icons.Default.Info, null, Modifier.size(52.dp), tint = MaterialTheme.colorScheme.primary)
        Text(stringResource(R.string.app_name), style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
        Text(stringResource(R.string.about_body), style = MaterialTheme.typography.bodyLarge)
        NoticeCard(
            Icons.Default.Security,
            stringResource(R.string.target_exact),
            stringResource(R.string.target_guard),
            false,
        )
        Text(
            "Payload: CVE-2026-43499 core66\n" +
                "KernelSU: 32601 (v3.3.0)\n" +
                "KMI: android15-6.6\n" +
                "License: Apache-2.0 / KernelSU components under their upstream licenses",
        )
    }
}

private fun managerInstalled(context: Context): Boolean =
    context.packageManager.getLaunchIntentForPackage(OnePlusPad3Target.MANAGER_PACKAGE) != null

private fun openManager(context: Context) {
    val launch = context.packageManager.getLaunchIntentForPackage(
        OnePlusPad3Target.MANAGER_PACKAGE,
    )
    if (launch == null) {
        Toast.makeText(context, R.string.manager_missing, Toast.LENGTH_LONG).show()
        return
    }
    context.startActivity(launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
}
