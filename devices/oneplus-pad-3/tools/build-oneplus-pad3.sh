#!/usr/bin/env bash
# Build one signer-matched OnePlus Pad 3 set: KernelSU LKM, ksud, Manager,
# CVE payload/helper, and the Root My OnePlus Pad 3 release APK.
#
# This is a local build only. It never invokes adb, installs, reboots, unlocks,
# or flashes a device unless --verify-device is requested (which is read-only).
set -euo pipefail

# Do not allow `bash -x` inherited by a caller to print credential assignments.
case "$-" in
  *x*) set +x; echo "[!] disabled shell xtrace before loading signing credentials" >&2 ;;
esac

ROOT=$(cd "$(dirname "$0")/.." && pwd)
if [ -n "${ROOT_MY_DEVICE_REPOSITORY_ROOT:-}" ]; then
  REPOSITORY_ROOT=$(cd "$ROOT_MY_DEVICE_REPOSITORY_ROOT" && pwd)
elif [ -d "$ROOT/../../src/kernelsu" ] && [ -d "$ROOT/../../devices" ]; then
  REPOSITORY_ROOT=$(cd "$ROOT/../.." && pwd)
else
  REPOSITORY_ROOT="$ROOT"
fi
KERNEL_RELEASE='6.6.118-android15-8-g2e6b9c3812c5-ab15114928-4k'
TARGET="oneplus-pad3/ex/$KERNEL_RELEASE"
TARGET_SLUG=${TARGET//\//_}
CORE='core66'
KSU_PIN='b0bc817b4e966aa6aa830834eaf6ef765d821d40'
RMD_PATCH_PIN='bf5bfa9ba0e7430611cca4b55ab12885df2d4eaa'
KSU_VERSION='32525'
KMI='android15-6.6'
DDK_IMAGE='ghcr.io/ylarod/ddk-min:android15-6.6-20260313'
MANAGER_PACKAGE='org.witaqua.pwn.kernelsu'
MANAGER_NAME='Root My Device KSU'
APP_PACKAGE='dev.tqmane.rootmyonepluspad3'
NDK_VERSION='29.0.14206865'
WORK="$ROOT/build/oneplus-pad3-fixed"
KSU_WORK="$WORK/KernelSU"
KERNELSU_SOURCE="$REPOSITORY_ROOT/src/kernelsu/KernelSU"
RMD="$REPOSITORY_ROOT/src/kernelsu/Root-My-Device-KSU"
VERIFY_DEVICE=0
ADB_SERIAL=''
RELEASE_CONFIRMED=0

usage() {
  cat <<'USAGE'
Usage: ./tools/build-oneplus-pad3.sh --release [--verify-device] [--serial SERIAL]

Builds the exact OPD2415_16.0.9.400(EX01) / android15-6.6 artifact set.
--release is required because a debug-signed Root app would not have the same
certificate as the KernelSU Manager.

Required signing environment (one identity is used for BOTH APKs):
  RMOP_KEYSTORE            path to a JKS/PKCS12 keystore
  RMOP_KEY_ALIAS           private-key alias
  RMOP_STORE_PASSWORD      keystore password, or set RMOP_PASSWORD_FILE
  RMOP_KEY_PASSWORD        key password; defaults to RMOP_STORE_PASSWORD
  RMOP_PASSWORD_FILE       optional file whose last nonempty field is the password

No keystore path, alias, or password is built into this repository.

Passwords are passed to keytool/apksigner through named environment variables,
not printed, added to Gradle properties, or placed in command-line arguments.

--verify-device runs the read-only exact target guard before building and
requires the connected device to report a locked/green boot state. The build
itself never mutates a connected device.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --release)
      RELEASE_CONFIRMED=1
      ;;
    --verify-device)
      VERIFY_DEVICE=1
      ;;
    --serial)
      [ "$#" -ge 2 ] || { echo "--serial requires a value" >&2; exit 2; }
      ADB_SERIAL=$2
      VERIFY_DEVICE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [ "$RELEASE_CONFIRMED" -ne 1 ]; then
  echo "--release is required so both APKs use the exact same certificate" >&2
  usage >&2
  exit 2
fi

for command_name in git docker python3 cargo rustup java keytool sha256sum stat sed awk make bpftool nm cc; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "missing command: $command_name" >&2
    exit 2
  }
done
python3 -c 'import elftools.elf.elffile' >/dev/null 2>&1 || {
  echo "missing Python dependency: pyelftools" >&2
  exit 2
}

if [ -z "${ANDROID_HOME:-}" ] && [ -d "$HOME/Android/Sdk" ]; then
  export ANDROID_HOME="$HOME/Android/Sdk"
fi
: "${ANDROID_HOME:?Set ANDROID_HOME to the Android SDK directory}"
NDK="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/$NDK_VERSION}"
TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64"
if [ ! -x "$TOOLCHAIN/bin/aarch64-linux-android35-clang" ]; then
  echo "Android NDK $NDK_VERSION not found at $NDK" >&2
  echo "Install it with: sdkmanager 'ndk;$NDK_VERSION'" >&2
  exit 2
fi
export ANDROID_NDK_HOME="$NDK"

resolve_android_build_tools() {
  local directory zipalign_help
  while IFS= read -r directory; do
    [ -x "$directory/apksigner" ] || continue
    [ -x "$directory/zipalign" ] || continue
    [ -x "$directory/aapt" ] || continue

    # The Pad 3 release uses 16 KiB ELF page alignment.  Probe the tool's
    # read-only help output here so an older PATH zipalign cannot let a long
    # build proceed and then reject `-P 16` during final packaging.
    zipalign_help=$("$directory/zipalign" -h 2>&1 || true)
    case "$zipalign_help" in
      *"-P <pagesize_kb>"*"Valid values for <pagesize_kb> are 4, 16"*)
        printf '%s\n' "$directory"
        return 0
        ;;
    esac
  done < <(
    find "$ANDROID_HOME/build-tools" -mindepth 1 -maxdepth 1 -type d -print \
      2>/dev/null | sort -Vr
  )
  return 1
}

ANDROID_BUILD_TOOLS=$(resolve_android_build_tools) || {
  echo "no coherent Android SDK build-tools with aapt, apksigner, and " \
       "zipalign -P 16 support found under $ANDROID_HOME/build-tools" >&2
  exit 2
}
APKSIGNER="$ANDROID_BUILD_TOOLS/apksigner"
ZIPALIGN="$ANDROID_BUILD_TOOLS/zipalign"
AAPT="$ANDROID_BUILD_TOOLS/aapt"
echo "==> Android build-tools: $ANDROID_BUILD_TOOLS"

[ -f "$ROOT/tools/kernel/build-ddk-module.sh" ] || {
  echo "missing LKM build helper: tools/kernel/build-ddk-module.sh" >&2
  exit 2
}
[ -d "$ROOT/src/targets/$TARGET" ] || {
  echo "missing exact target directory: src/targets/$TARGET" >&2
  echo "Do not substitute another SM8750 target." >&2
  exit 2
}
COMMON_PATCH_DIR="$RMD/patches/$KSU_VERSION/common"
[ -d "$COMMON_PATCH_DIR" ] || {
  echo "missing KernelSU $KSU_VERSION common patches: $COMMON_PATCH_DIR" >&2
  exit 2
}
if git -C "$RMD" rev-parse --git-dir >/dev/null 2>&1; then
  actual_rmd_patch_pin=$(git -C "$RMD" rev-parse HEAD)
  [ "$actual_rmd_patch_pin" = "$RMD_PATCH_PIN" ] || {
    echo "Root-My-Device-KSU pin mismatch: $actual_rmd_patch_pin != $RMD_PATCH_PIN" >&2
    exit 2
  }
fi

# The release build supplies its only two compiler additions itself: the
# helper/ksud digest pins below.  Refuse every inherited compiler or make flag
# here, not just a visible -D spelling.  MAKEFLAGS can inject EXTRA_CFLAGS and
# an apparently unrelated `-include` can define an unsafe route after the exact
# profile verifier has inspected the source tree.
for flag_variable in \
  EXTRA_CFLAGS PAYLOAD_EXTRA_CFLAGS HELPER_EXTRA_CFLAGS COMMON_CFLAGS \
  CFLAGS CPPFLAGS LDFLAGS MAKEFLAGS MFLAGS MAKEOVERRIDES; do
  flag_value=${!flag_variable-}
  [ -z "$flag_value" ] || {
    echo "refusing inherited $flag_variable in the exact Pad 3 release build" >&2
    exit 2
  }
done

GENERATED_PROFILE_DIR="$ROOT/generated/oneplus-pad-3"
GENERATED_PROFILE_REQUIRED=(kernel vmlinux Module.symvers kernel.btf kallsyms.txt)
GENERATED_PROFILE_MISSING=()
for generated_name in "${GENERATED_PROFILE_REQUIRED[@]}"; do
  [ -s "$GENERATED_PROFILE_DIR/$generated_name" ] || \
    GENERATED_PROFILE_MISSING+=("$generated_name")
done

HAVE_EXACT_GENERATED_PROFILE=1
if [ "${#GENERATED_PROFILE_MISSING[@]}" -ne 0 ]; then
  HAVE_EXACT_GENERATED_PROFILE=0
  if [ "${RMOP_REQUIRE_GENERATED_PROFILE:-0}" = 1 ]; then
    echo "missing exact OnePlus Pad 3 generated analysis input(s): ${GENERATED_PROFILE_MISSING[*]}" >&2
    echo "Generate/copy them under $GENERATED_PROFILE_DIR or unset RMOP_REQUIRE_GENERATED_PROFILE." >&2
    exit 2
  fi
  echo "[WARN] exact OnePlus Pad 3 generated analysis bundle is incomplete: ${GENERATED_PROFILE_MISSING[*]}" >&2
  echo "[WARN] running committed-profile/source checks and continuing the reproducible build." >&2
  echo "[WARN] set RMOP_REQUIRE_GENERATED_PROFILE=1 to make the full local kernel/vmlinux/BTF audit mandatory." >&2
else
  echo "==> verify exact generated OnePlus Pad 3 kernel/profile bundle"
  python3 "$ROOT/tools/verify-profile.py"
fi

# These checks are source/profile contract tests and do not require proprietary
# locally extracted firmware analysis artifacts. Always run them.
python3 "$ROOT/tools/verify-profile.py" --mode4-contract-self-test
python3 "$ROOT/tools/verify-a3-source-contract.py"
python3 "$ROOT/tools/verify-profile.py" --reclaim-contract-self-test
PAD3_TARGET_HEADER="$ROOT/src/targets/$TARGET/target-core66.h"
PAD3_STRUCT_OFFSETS="$ROOT/src/targets/$TARGET/struct-offsets.h"
uuid_feature_definitions=$(
  grep -Ec \
    '^[[:space:]]*#define[[:space:]]+SLIDE_USE_RANDOM_UUID_LEAK[[:space:]]+1[[:space:]]*$' \
    "$PAD3_TARGET_HEADER" || true
)
[ "$uuid_feature_definitions" -eq 1 ] || {
  echo "Pad 3 target must define SLIDE_USE_RANDOM_UUID_LEAK as exact 1 once: " \
       "$PAD3_TARGET_HEADER" >&2
  exit 2
}
diagnostic_feature_definitions=$(
  grep -REh \
    '^[[:space:]]*#define[[:space:]]+PAD3_KERNELSNITCH_DIAGNOSTICS[[:space:]]+1[[:space:]]*$' \
    "$ROOT/src/targets" 2>/dev/null | wc -l
)
[ "$diagnostic_feature_definitions" -eq 1 ] || {
  echo "Pad 3 KernelSnitch diagnostic feature must be exact 1 and defined " \
       "in exactly one target header; found=$diagnostic_feature_definitions" >&2
  exit 2
}
if grep -REq 'PAD3_SLIDE_KERNELSNITCH_ACCEPT_MIN' \
    "$ROOT/src"; then
  echo "obsolete cross-stage KernelSnitch route threshold survived" >&2
  exit 2
fi
if grep -REq 'PAD3_FOPS_KERNELSNITCH_ACCEPT_MIN' \
    "$ROOT/src"; then
  echo "unvalidated FOPS KernelSnitch timing route threshold survived" >&2
  exit 2
fi
CORE66_OFFSETS="$ROOT/src/payloads/CVE-2026-43499/core66/offsets.h"
CORE66_DEVICE_OFFSETS="$ROOT/src/payloads/CVE-2026-43499/core66/device_offsets.h"
CORE66_MAIN="$ROOT/src/payloads/CVE-2026-43499/core66/main.c"
CORE66_COMMON="$ROOT/src/payloads/CVE-2026-43499/core66/common.h"
CORE66_UTIL="$ROOT/src/payloads/CVE-2026-43499/core66/util.c"
CORE66_SLIDE="$ROOT/src/payloads/CVE-2026-43499/core66/slide.c"
CORE66_FOPS="$ROOT/src/payloads/CVE-2026-43499/core66/fops.c"
CORE66_PIPE="$ROOT/src/payloads/CVE-2026-43499/core66/pipe.c"
CORE66_ROOT="$ROOT/src/payloads/CVE-2026-43499/core66/root.c"
CORE66_KERNELSNITCH="$ROOT/src/payloads/CVE-2026-43499/core66/kernelsnitch/kernelsnitch.h"
PRELOAD_SRC="$ROOT/src/payloads/CVE-2026-43499/preload.c"

# Pad 3 owns the live KPHYS helper and reclaim hardening macros.  Compile the
# two affected core66 translation units against a legacy feature-off profile
# so an unconditional target-only reference cannot survive source review.
FEATURE_OFF_DIR="$ROOT/tools/fixtures/core66-feature-off"
for feature_off_tu in "$CORE66_UTIL" "$CORE66_SLIDE" "$CORE66_FOPS"; do
  "$TOOLCHAIN/bin/aarch64-linux-android35-clang" \
    -fsyntax-only -O2 -Wall -Wextra -Werror \
    -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function \
    -DGHOSTLOCK_PRELOAD=1 \
    -I"$ROOT/src/payloads/CVE-2026-43499/core66" \
    -I"$ROOT/src/payloads/CVE-2026-43499" \
    -I"$FEATURE_OFF_DIR" -I"$ROOT/src" \
    -DTARGET_HEADER='"target-core66.h"' \
    -DTARGET_CONFIG_H='"target-core66.h"' \
    -DTARGET_KERNEL_RELEASE='"feature-off-compile-fixture"' \
    "$feature_off_tu"
done
for source_guard in \
  "$CORE66_UTIL:fops mode4 hybrid owner-safe" \
  "$CORE66_COMMON:#ifndef SKB_RECLAIM_SENDS" \
  "$CORE66_COMMON:#define SKB_RECLAIM_SENDS 4" \
  "$CORE66_COMMON:_Static_assert(FOPS_OFF + SKB_DATA_DELTA == 0x100" \
  "$CORE66_UTIL:Pad3 head guard ready groups=1 sends=8 frees=4 holders=4" \
  "$CORE66_UTIL:pad3_prepare_head_guards(head_guard_sv)" \
  "$CORE66_UTIL:pad3_head_guards_intact(head_guard_sv)" \
  "$CORE66_UTIL:pad3_close_head_guards(head_guard_sv)" \
  "$CORE66_UTIL:effective_sndbuf < SKB_RECLAIM_MIN_EFFECTIVE_SNDBUF" \
  "$CORE66_UTIL:target_close_ret = close(memfd_leak);" \
  "$CORE66_UTIL:reclaim_results[0] = sendmsg(reclaim_sv[0], &msg, MSG_DONTWAIT);" \
  "$CORE66_UTIL:slab_off % MM_STRUCT_SZ != 0" \
  "$CORE66_UTIL:leaked_slot >= 25" \
  "$CORE66_UTIL:Pad3 mm leak validated pointer=" \
  "$CORE66_UTIL:fake_parent = fake_fops;" \
  "$CORE66_UTIL:fake_right = misc_fops;" \
  "$CORE66_UTIL:long ret = syscall(274, tid, &attr, 0);" \
  "$CORE66_UTIL:return ret;" \
  "$CORE66_UTIL:return open(ashmem_path, O_RDWR | O_CLOEXEC);" \
  "$CORE66_UTIL:last_kernel_page_ks_accept_min = 0;" \
  "$CORE66_UTIL:last_kernel_page_ks_accept_min = ks->collision_accept_min;" \
  "$CORE66_UTIL:size_t kernel_page_kernelsnitch_accept_min(void)" \
  "$CORE66_UTIL:kernelsnitch_find_collisions(ks);" \
  "$CORE66_UTIL:SYSCHK(waitpid(child_leak, NULL, 0));" \
  "$CORE66_UTIL:close(reclaim_sv[i]);" \
  "$CORE66_UTIL:free(skb_buf);" \
  "$CORE66_KERNELSNITCH:volatile size_t collision_accept_min;" \
  "$CORE66_KERNELSNITCH:volatile size_t collision_accept_max;" \
  "$CORE66_KERNELSNITCH:volatile size_t collision_reject_max;" \
  "$CORE66_KERNELSNITCH:_Atomic size_t increase_ready;" \
  "$CORE66_KERNELSNITCH:_Atomic uint32_t leak_child_start_state;" \
  "$CORE66_KERNELSNITCH:memory_order_release" \
  "$CORE66_KERNELSNITCH:memory_order_acquire" \
  "$CORE66_KERNELSNITCH:if (create_rc != 0)" \
  "$CORE66_KERNELSNITCH:if (elapsed_ms >= timeout_ms)" \
  "$CORE66_KERNELSNITCH:KernelSnitch waiter pile incomplete; collision scan refused" \
  "$CORE66_UTIL:pad3_leak_child_park_until_released()" \
  "$CORE66_UTIL:pad3_wait_leak_child_parked()" \
  "$CORE66_UTIL:pad3_release_leak_child()" \
  "$CORE66_UTIL:pad3_validate_leak_adjacency_pins()" \
  "$CORE66_UTIL:valid_pins += pre_ctx.memfds[i] >= 0" \
  "$CORE66_UTIL:Pad3 mm adjacency pins children=50/50 pins=50/50" \
  "$CORE66_UTIL:Pad3 KernelSnitch leak child released after post-mm pin exact=1" \
  "$CORE66_MAIN:int memfd_leak = -1;" \
  "$CORE66_KERNELSNITCH:ks->collision_accept_min =" \
  "$CORE66_KERNELSNITCH:MAP_ANON|MAP_SHARED" \
  "$CORE66_SLIDE:#if defined(PAD3_KERNELSNITCH_DIAGNOSTICS)" \
  "$CORE66_SLIDE:Pad3 slide KernelSnitch diagnostic accepted=" \
  "$CORE66_SLIDE:no-route-gate=1" \
  "$CORE66_FOPS:if (custom_mode == 4)" \
  "$CORE66_FOPS:custom_mode == 4 ? calls > 0" \
  "$CORE66_FOPS:acknowledged_seq = atomic_load_explicit(&consumer_quiesced_seq," \
  "$CORE66_FOPS:atomic_store(&pi_cleanup_required, 1)" \
  "$CORE66_FOPS:atomic_store(&pi_cleanup_seq, route_attempt)" \
  "$CORE66_FOPS:cleanup_main_waiter_pi_state(fd)" \
  "$CORE66_FOPS:pi_cleanup_fail_stop(fd)" \
  "$CORE66_FOPS:commit_result < 0" \
  "$CORE66_FOPS:int state_unknown = !redirect_restored || pipe_restore_unknown ||" \
  "$CORE66_FOPS:abort_ok != 1 || auxiliary_dirty_unknown ||" \
  "$CORE66_PIPE:PIPE_PREPARE_NONFATAL" \
  "$CORE66_PIPE:pad3_wait_leak_child_parked()" \
  "$CORE66_PIPE:pad3_release_leak_child()" \
  "$CORE66_PIPE:pipe_wait_child_exit_zero_checked(leak_child)" \
  "$CORE66_PIPE:WIFEXITED(status) && WEXITSTATUS(status) == 0" \
  "$CORE66_PIPE:Pad3 PIPE KernelSnitch leak child released after" \
  "$CORE66_PIPE:PIPE_MARKER_WRITE_NONFATAL" \
  "$CORE66_PIPE:if (pipebuf_page_base == 0) { return 0; }" \
  "$CORE66_FOPS:validate_runtime_kernel_phys_variables(fd)" \
  "$CORE66_FOPS:kernel physical live check=" \
  "$CORE66_MAIN:atomic_exchange(&pipe_prepare_request, 0)" \
  "$CORE66_MAIN:pipe prepare request accepted" \
  "$CORE66_MAIN:pthread_sigmask(SIG_BLOCK" \
  "$CORE66_MAIN:SIGPIPE" \
  "$CORE66_MAIN:atomic_load_explicit(&pi_cleanup_fail_stop_active" \
  "$CORE66_MAIN:PR_SET_PDEATHSIG, 0" \
  "$CORE66_MAIN:consumer_quiesced_seq" \
  "$CORE66_MAIN:pi_cleanup_required" \
  "$CORE66_MAIN:pi_cleanup_seq" \
  "$CORE66_MAIN:atomic_store_explicit(&consumer_quiesced_seq, seq," \
  "$CORE66_MAIN:pi_cleanup_fail_stop" \
  "$CORE66_ROOT:waiter PI cleanup exact" \
  "$CORE66_ROOT:waiter PI cleanup cached" \
  "$CORE66_ROOT:root_a2_snapshot_current_retry" \
  "$CORE66_ROOT:completed_ms - started_ms > ROOT_A2_SNAPSHOT_RETRY_DEADLINE_MS" \
  "$CORE66_ROOT:dprintf(STDERR_FILENO," \
  "$CORE66_ROOT:atomic_store_explicit(&pi_cleanup_fail_stop_active" \
  "$CORE66_ROOT:PR_SET_PDEATHSIG, 0" \
  "$CORE66_ROOT:block_pi_cleanup_termination_signals(NULL)" \
  "$CORE66_ROOT:atomic_load(&route_done) != 0" \
  "$CORE66_ROOT:atomic_load(&pi_cleanup_required) != 1" \
  "$CORE66_ROOT:atomic_load(&pi_cleanup_seq) !=" \
  "$CORE66_ROOT:atomic_load_explicit(&consumer_quiesced_seq, memory_order_acquire);" \
  "$CORE66_ROOT:__attribute__((noreturn))" \
  "$CORE66_ROOT:pi_cleanup_fail_stop" \
  "$CORE66_ROOT:memcmp(child->sid, parent_sid, sizeof(parent_sid)) != 0" \
  "$CORE66_ROOT:READ_WAITER_PI_SNAPSHOT(first)" \
  "$CORE66_ROOT:READ_WAITER_PI_SNAPSHOT(second)" \
  "$CORE66_ROOT:READ_WAITER_PI_SNAPSHOT(after)" \
  "$PRELOAD_SRC:dirty supervisor timeout no SIGKILL" \
  "$PRELOAD_SRC:CURRENT_BOOT_DIRTY_RETAIN supervisor parked; no retry child=" \
  "$PRELOAD_SRC:pid_t process_id = getpid();" \
  "$PRELOAD_SRC:pid_t thread_id = (pid_t)syscall(SYS_gettid);" \
  "$PRELOAD_SRC:process_id != thread_id" \
  "$PRELOAD_SRC:atomic_store_explicit(&payload_state->dirty, 1, memory_order_release);" \
  "$PRELOAD_SRC:PR_SET_PDEATHSIG, 0" \
  "$PRELOAD_SRC:block_dirty_retention_signals()" \
  "$PRELOAD_SRC:dprintf(STDERR_FILENO," \
  "$PRELOAD_SRC:SIGTERM" \
  "$PRELOAD_SRC:SIGHUP" \
  "$PRELOAD_SRC:SIGINT" \
  "$PRELOAD_SRC:SIGQUIT" \
  "$PRELOAD_SRC:SIGPIPE" \
  "$PAD3_TARGET_HEADER:#define P0_DISABLE_RUNTIME_PSELECT_LAYOUT_OVERRIDE 1" \
  "$PAD3_TARGET_HEADER:#define DIRECT_WAITER_PI_CLEANUP 1" \
  "$PAD3_TARGET_HEADER:#define KPHYS_RUNTIME_LIVE_VALIDATION 1" \
  "$PAD3_TARGET_HEADER:#define SKB_RECLAIM_PAD3_HARDENING       1" \
  "$PAD3_TARGET_HEADER:#define SKB_RECLAIM_SENDS                4" \
  "$PAD3_TARGET_HEADER:#define SKB_RECLAIM_TRUESIZE             0x9100" \
  "$PAD3_TARGET_HEADER:#define SKB_RECLAIM_MIN_EFFECTIVE_SNDBUF 0x24401" \
  "$PAD3_TARGET_HEADER:#define SKB_HEAD_GUARD_GROUPS            1" \
  "$PAD3_TARGET_HEADER:#define PAD3_KERNELSNITCH_DIAGNOSTICS 1" \
  "$PAD3_TARGET_HEADER:#define PAD3_KERNELSNITCH_READY_BARRIER 1" \
  "$PAD3_TARGET_HEADER:#define PAD3_KERNELSNITCH_READY_TIMEOUT_MS 10000" \
  "$PAD3_TARGET_HEADER:#define PAD3_KERNELSNITCH_CHILD_START_BARRIER 1" \
  "$PAD3_TARGET_HEADER:#define PAD3_KERNELSNITCH_CHILD_START_TIMEOUT_MS 10000" \
  "$PAD3_TARGET_HEADER:#define PSELECT_EXPECTED_READY 8" \
  "$PAD3_STRUCT_OFFSETS:#define TASK_STACK_OFF              0x38" \
  "$PAD3_STRUCT_OFFSETS:#define TASK_THREAD_SIZE            0x4000" \
  "$PAD3_STRUCT_OFFSETS:#define RT_MUTEX_WAITER_SIZE       0x70"; do
  source_path=${source_guard%%:*}
  source_marker=${source_guard#*:}
  grep -Fq "$source_marker" "$source_path" || {
    echo "missing exact Pad 3 mode4/PI source guard in $source_path: " \
         "$source_marker" >&2
    exit 2
  }
done
for source_guard in \
  "#define ROOT_A2_SNAPSHOT_RETRY_ATTEMPTS 4" \
  "#define ROOT_A2_SNAPSHOT_RETRY_DEADLINE_MS 500"; do
  grep -Fq "$source_guard" "$CORE66_COMMON" "$CORE66_ROOT" || {
    echo "missing exact Pad 3 snapshot retry source guard: $source_guard" >&2
    exit 2
  }
done
if grep -Fq 'kill(child, SIGKILL)' "$PRELOAD_SRC"; then
  echo "dirty supervisor timeout must not SIGKILL a possibly PI-stale attempt" >&2
  exit 2
fi
for forbidden_dirty_supervisor in \
  'pr_error("current-boot dirty supervisor timeout no SIGKILL' \
  'pr_error("dirty child retention waitpid failed'; do
  if grep -Fq "$forbidden_dirty_supervisor" "$PRELOAD_SRC"; then
    echo "dirty supervisor retention must use nonfatal logging: " \
         "$forbidden_dirty_supervisor" >&2
    exit 2
  fi
done
for forbidden_pipe_prepare in \
  'SYSCHK(' \
  'pr_error(' \
  'abort('; do
  if grep -Fq "$forbidden_pipe_prepare" "$CORE66_PIPE"; then
    echo "pipe prepare/install must be nonfatal after PI cleanup is armed: " \
         "$forbidden_pipe_prepare" >&2
    exit 2
  fi
done
# The one `_exit(0)` belongs to the process created by the explicit
# `fork() == 0` branch.  That child must be allowed to terminate so the live
# waiter/coordinator observes EOF as base=0; normal `exit()` remains forbidden
# everywhere in this translation unit.  verify-profile.py additionally binds
# this exit to pipe_prepare_child_process's exact control-flow contract.
if grep -Eq '(^|[^_[:alnum:]])exit\(' "$CORE66_PIPE"; then
  echo "pipe prepare/install contains a process-wide exit()" >&2
  exit 2
fi
pipe_child_exit_count=$(grep -oF '_exit(' "$CORE66_PIPE" | wc -l)
if [ "$pipe_child_exit_count" -ne 1 ] ||
   ! grep -Fq 'pipe_prepare_child_process(' "$CORE66_PIPE"; then
  echo "pipe prepare fork-child exit contract mismatch: count=" \
       "$pipe_child_exit_count" >&2
  exit 2
fi
for source_guard in \
  "$CORE66_OFFSETS:off_slide_random_boot_id_data, off_slide_sysctl_bootid" \
  "$CORE66_DEVICE_OFFSETS:.off_slide_random_boot_id_data = SLIDE_RANDOM_BOOT_ID_DATA_OFF" \
  "$CORE66_DEVICE_OFFSETS:.off_slide_sysctl_bootid = SLIDE_SYSCTL_BOOTID_OFF" \
  "$CORE66_MAIN:active_offsets->off_slide_random_boot_id_data" \
  "$CORE66_MAIN:active_offsets->off_slide_sysctl_bootid"; do
  source_path=${source_guard%%:*}
  source_marker=${source_guard#*:}
  grep -Fq "$source_marker" "$source_path" || {
    echo "missing distinct Pad 3 slide runtime-offset guard in $source_path: " \
         "$source_marker" >&2
    exit 2
  }
done
if grep -Fq 'off_slide_boot_id' \
    "$CORE66_OFFSETS" "$CORE66_DEVICE_OFFSETS" "$CORE66_MAIN"; then
  echo "legacy collapsed off_slide_boot_id survived in the core66 runtime table" >&2
  exit 2
fi
case "${EXTRA_CFLAGS:-}" in
  *P0_ENABLE_UNSAFE_DIRECT_ROOT_ROUTE*|*P0_ENABLE_UNSAFE_PHYS_LOAD_OVERRIDE*|*P0_ENABLE_UNSAFE_RAW_WQ_ROUTE*)
    echo "unsafe root-route/workqueue/physical-load opt-in is forbidden in the Pad 3 release build" >&2
    exit 2
    ;;
esac
for required in \
  'P0_DISABLE_DIRECT_ROOT_ROUTE' \
  '!defined(P0_ENABLE_UNSAFE_DIRECT_ROOT_ROUTE)' \
  'payload_primitive_is_dirty()'; do
  grep -Fq "$required" "$CORE66_MAIN" || {
    echo "missing release root-route gate in $CORE66_MAIN: $required" >&2
    exit 2
  }
done
for required in \
  'P0_DISABLE_RAW_WORKQUEUE_ROUTE' \
  '#if defined(P0_ENABLE_UNSAFE_RAW_WQ_ROUTE)' \
  'SYS_execveat' \
  'root_a3_spawn_stopped_child' \
  'root_a3_patch_stopped_child' \
  'root_a3_validate_committed' \
  'root_a3_spawn_watchdog' \
  'SO_PEERCRED'; do
  grep -Fq "$required" "$CORE66_ROOT" "$ROOT/src/targets/$TARGET/target-core66.h" || {
    echo "missing release self-cred/raw-workqueue gate: $required" >&2
    exit 2
  }
done
APP_ROOT_MODEL="$ROOT/app/src/main/java/dev/tqmane/rootmyonepluspad3/RootViewModel.kt"
APP_RECEIPT_PARSER="$ROOT/app/src/main/java/dev/tqmane/rootmyonepluspad3/ModuleCompletionReceipt.kt"
for required in \
  'ByteArray(16).also(SecureRandom()::nextBytes)' \
  '.putString(RECEIPT_RUN_ID, nonce)' \
  '"run-id=$runId"' \
  'kernelLive && moduleMarkerMatchesRequest()' \
  'ModuleCompletionReceipt.matches(probe, bootId, runId, ksudSha256)'; do
  grep -Fq "$required" "$APP_ROOT_MODEL" || {
    echo "missing private nonce/public receipt UI gate in $APP_ROOT_MODEL: $required" >&2
    exit 2
  }
done
for required in \
  'Regex("[0-9a-f]{32}")' \
  'Regex("[0-9a-f]{64}")' \
  'append(" uid=0 gid=0 mode=644 nlink=1\n")' \
  'append("version=1\n")' \
  'append("run_id=").append(expectedRunId)' \
  'append("ksud_sha256=").append(expectedKsudSha256)' \
  'return normalized == expected'; do
  grep -Fq "$required" "$APP_RECEIPT_PARSER" || {
    echo "missing exact nonce-bound receipt parser in $APP_RECEIPT_PARSER: $required" >&2
    exit 2
  }
done

if [ "$VERIFY_DEVICE" -eq 1 ]; then
  verify_args=(--require-locked)
  if [ -n "$ADB_SERIAL" ]; then
    verify_args+=(--serial "$ADB_SERIAL")
  fi
  python3 "$ROOT/tools/verify-target.py" "${verify_args[@]}"
fi

# One canonical identity drives the module's accepted certificate, the Manager
# APK, and the Root app. There are intentionally no separate Manager variables.
: "${RMOP_KEYSTORE:?Set RMOP_KEYSTORE to a JKS/PKCS12 keystore}"
: "${RMOP_KEY_ALIAS:?Set RMOP_KEY_ALIAS to a private-key alias}"
RMOP_PASSWORD_FILE=${RMOP_PASSWORD_FILE:-}
if [ -z "${RMOP_STORE_PASSWORD:-}" ]; then
  [ -n "$RMOP_PASSWORD_FILE" ] || {
    echo "set RMOP_STORE_PASSWORD or RMOP_PASSWORD_FILE" >&2
    exit 2
  }
  [ -f "$RMOP_PASSWORD_FILE" ] || {
    echo "password file not found: $RMOP_PASSWORD_FILE" >&2
    exit 2
  }
  # Do not print the credential. Consume only the final field from the final
  # nonempty line and retain it in this process environment.
  RMOP_STORE_PASSWORD=$(awk 'NF { value=$NF } END { print value }' "$RMOP_PASSWORD_FILE")
fi
RMOP_KEY_PASSWORD=${RMOP_KEY_PASSWORD:-$RMOP_STORE_PASSWORD}
# Environment overrides arrive with Bash's export attribute set. Clear it now
# so subsequent git/Docker/Cargo children cannot inherit either secret; the
# four signing invocations below opt in again only for their own child scope.
export -n RMOP_STORE_PASSWORD RMOP_KEY_PASSWORD
cleanup_credentials() {
  unset RMOP_STORE_PASSWORD RMOP_KEY_PASSWORD
  unset ORG_GRADLE_PROJECT_KEYSTORE_PASSWORD ORG_GRADLE_PROJECT_KEY_PASSWORD
}
trap cleanup_credentials EXIT

RMOP_KEYSTORE=$(readlink -f "$RMOP_KEYSTORE")
export RMOP_KEYSTORE
[ -f "$RMOP_KEYSTORE" ] || { echo "keystore not found: $RMOP_KEYSTORE" >&2; exit 2; }
[ -n "$RMOP_STORE_PASSWORD" ] || { echo "empty keystore password" >&2; exit 2; }
if [ $((8#$(stat -c '%a' "$RMOP_KEYSTORE") & 8#077)) -ne 0 ]; then
  echo "[!] warning: keystore is group/other-accessible: $RMOP_KEYSTORE" >&2
fi
if [ -f "$RMOP_PASSWORD_FILE" ] && [ $((8#$(stat -c '%a' "$RMOP_PASSWORD_FILE") & 8#077)) -ne 0 ]; then
  echo "[!] warning: password file is group/other-accessible: $RMOP_PASSWORD_FILE" >&2
fi

key_metadata=$(RMOP_STORE_PASSWORD="$RMOP_STORE_PASSWORD" keytool -list -v \
  -keystore "$RMOP_KEYSTORE" \
  -storepass:env RMOP_STORE_PASSWORD \
  -alias "$RMOP_KEY_ALIAS" 2>&1) || {
  echo "unable to open alias $RMOP_KEY_ALIAS in $RMOP_KEYSTORE" >&2
  exit 3
}
printf '%s\n' "$key_metadata" | grep -q 'PrivateKeyEntry' || {
  echo "alias $RMOP_KEY_ALIAS is not a PrivateKeyEntry" >&2
  exit 3
}
unset key_metadata

mkdir -p "$WORK"
CERT_DER="$WORK/manager-cert.der"
rm -f "$CERT_DER"
RMOP_STORE_PASSWORD="$RMOP_STORE_PASSWORD" keytool -exportcert -noprompt \
  -keystore "$RMOP_KEYSTORE" \
  -storepass:env RMOP_STORE_PASSWORD \
  -alias "$RMOP_KEY_ALIAS" \
  -file "$CERT_DER" >/dev/null
MANAGER_CERT_SIZE_DEC=$(stat -c '%s' "$CERT_DER")
if [ "$MANAGER_CERT_SIZE_DEC" -gt 1024 ]; then
  echo "Manager certificate is $MANAGER_CERT_SIZE_DEC bytes; KernelSU limit is 1024" >&2
  exit 3
fi
printf -v MANAGER_CERT_SIZE '0x%04x' "$MANAGER_CERT_SIZE_DEC"
MANAGER_CERT_HASH=$(sha256sum "$CERT_DER" | awk '{print $1}')
echo "==> signer DER size=$MANAGER_CERT_SIZE_DEC sha256=$MANAGER_CERT_HASH"

case "$KSU_WORK" in
  "$ROOT"/build/*) rm -rf "$KSU_WORK" ;;
  *) echo "refusing to remove unexpected KSU work path: $KSU_WORK" >&2; exit 3 ;;
esac
if git -C "$KERNELSU_SOURCE" rev-parse --git-dir >/dev/null 2>&1; then
  git clone --quiet "$KERNELSU_SOURCE" "$KSU_WORK"
else
  echo "==> cloning pinned KernelSU upstream"
  git clone --quiet https://github.com/tiann/KernelSU.git "$KSU_WORK"
fi
git -C "$KSU_WORK" checkout --quiet --detach "$KSU_PIN"
actual_pin=$(git -C "$KSU_WORK" rev-parse HEAD)
[ "$actual_pin" = "$KSU_PIN" ] || {
  echo "KernelSU pin mismatch: $actual_pin != $KSU_PIN" >&2
  exit 3
}
actual_version=$((30000 + $(git -C "$KSU_WORK" rev-list --count HEAD)))
[ "$actual_version" = "$KSU_VERSION" ] || {
  echo "KernelSU history is shallow/wrong: version=$actual_version expected=$KSU_VERSION" >&2
  exit 3
}

shopt -s nullglob
patches=("$COMMON_PATCH_DIR"/*.patch)
[ "${#patches[@]}" -gt 0 ] || {
  echo "no common patches found in $COMMON_PATCH_DIR" >&2
  exit 3
}
DEVICE_PATCH_DIR="$RMD/patches/$KSU_VERSION/devices/oneplus-pad3"
device_patches=()
if [ -d "$DEVICE_PATCH_DIR" ]; then
  device_patches=("$DEVICE_PATCH_DIR"/*.patch)
fi
if [ "${#device_patches[@]}" -eq 0 ]; then
  echo "missing required Pad 3 patch set in the Root-My-Device-KSU submodule: $DEVICE_PATCH_DIR" >&2
  exit 3
fi
patches+=("${device_patches[@]}")
shopt -u nullglob

PATCH_NORMALIZED="$WORK/normalized-patches"
rm -rf "$PATCH_NORMALIZED"
mkdir -p "$PATCH_NORMALIZED"
patch_index=0
for patch_file in "${patches[@]}"; do
  patch_index=$((patch_index + 1))
  normalized="$PATCH_NORMALIZED/$patch_index-$(basename "$patch_file")"
  sed 's/\r$//' "$patch_file" > "$normalized"
  echo "==> apply $(basename "$patch_file")"
  git -C "$KSU_WORK" apply --check "$normalized"
  git -C "$KSU_WORK" apply "$normalized"
done
git -C "$KSU_WORK" diff --check

# Marker strings prove that patches compiled, not that their ordering is safe.
# Verify the completion contract in the applied source before starting the
# expensive DDK build: ordinary service stage -> monitored Vector service ->
# live socket -> zygote/system_server boundary -> official Vector CLI -> bounded
# boot-completed -> trusted receipt. The enforcing-state module-retry path is
# checked independently and never reloads kernelsu.ko. The helper publishes the public mirror only after it
# independently verifies that receipt and every final integrity condition.
python3 - \
  "$KSU_WORK/userspace/ksud/src/late_load.rs" \
  "$KSU_WORK/userspace/ksud/src/module.rs" \
  "$KSU_WORK/userspace/ksud/src/init_event.rs" \
  "$KSU_WORK/userspace/ksud/src/utils.rs" \
  "$KSU_WORK/userspace/ksud/src/ksucalls.rs" \
  "$KSU_WORK/userspace/ksud/src/cli.rs" \
  "$ROOT/src/payloads/su_daemon/late_load.c" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")
module_path = Path(sys.argv[2])
module_source = module_path.read_text(encoding="utf-8")
init_event_path = Path(sys.argv[3])
init_event_source = init_event_path.read_text(encoding="utf-8")
utils_path = Path(sys.argv[4])
utils_source = utils_path.read_text(encoding="utf-8")
ksucalls_path = Path(sys.argv[5])
ksucalls_source = ksucalls_path.read_text(encoding="utf-8")
cli_path = Path(sys.argv[6])
cli_source = cli_path.read_text(encoding="utf-8")
helper_path = Path(sys.argv[7])
helper_source = helper_path.read_text(encoding="utf-8")

def locate(pattern: str, label: str, haystack: str = source) -> int:
    match = re.search(pattern, haystack, re.MULTILINE)
    if match is None:
        raise SystemExit(f"missing {label} in {path}")
    return match.start()

def section(start_marker: str, end_marker: str, label: str) -> tuple[str, int]:
    start = source.find(start_marker)
    end = source.find(end_marker, start + 1)
    if start < 0 or end <= start:
        raise SystemExit(f"missing {label} section in {path}")
    return source[start:end], start

# Catch the 0011 receipt-FD scope regression before the expensive DDK/Rust
# build. `public_receipts` is a parameter only inside the publisher and a local
# only inside module-retry; success/failure finalization must keep using the
# retained authority FD.
finalizer_source, _ = section(
    "fn finalize_post_load_success(",
    "fn cleanup_post_load_failure(",
    "post-load success finalizer",
)
failure_cleanup_source, _ = section(
    "fn cleanup_post_load_failure(",
    "fn public_log_name(",
    "post-load failure cleanup",
)
for label, region in (
    ("post-load success finalizer", finalizer_source),
    ("post-load failure cleanup", failure_cleanup_source),
):
    if re.search(r"(?m)^\s+public_receipts,$", region):
        raise SystemExit(
            f"out-of-scope bare public_receipts survived in {label}: {path}"
        )
if "publish_public_receipt_exact(&authorities.public_receipts, run_id, content)?;" not in finalizer_source:
    raise SystemExit(f"success finalizer lost retained public receipt authority in {path}")
if not re.search(
    r'verify_receipt_exact\(\s*&authorities\.public_receipts,\s*"\.ksu-late-load-modules-ok"',
    finalizer_source,
):
    raise SystemExit(f"success finalizer public receipt verification is not authority-bound in {path}")
if not re.search(
    r'unlink_sync_prove_absent\(\s*&authorities\.public_receipts,\s*"/data/local/tmp"',
    failure_cleanup_source,
):
    raise SystemExit(f"failure cleanup public receipt rollback is not authority-bound in {path}")
if "use std::os::unix::process::CommandExt;" not in source:
    raise SystemExit(f"monitored Vector launcher lost pre-exec support in {path}")

runtime_env, _ = section(
    "const ANDROID_RUNTIME_ROOTS:",
    "const VECTOR_SERVICE_MARKER:",
    "Android runtime environment constants",
)
for required in (
    '("ANDROID_ROOT", "/system", 0, 0, 0o755)',
    '("ANDROID_DATA", "/data", 1000, 1000, 0o771)',
    '"ANDROID_ART_ROOT"',
    '"/apex/com.android.art"',
    '"ANDROID_I18N_ROOT"',
    '"/apex/com.android.i18n"',
    '"ANDROID_TZDATA_ROOT"',
    '"/apex/com.android.tzdata"',
    '"BOOTCLASSPATH"',
    '"DEX2OATBOOTCLASSPATH"',
    '"SYSTEMSERVERCLASSPATH"',
    '"STANDALONE_SYSTEMSERVER_JARS"',
):
    if required not in runtime_env:
        raise SystemExit(f"missing mandatory Android runtime environment constant in {path}: {required}")

runtime_restore, _ = section(
    "fn validate_android_runtime_root(",
    "fn staged_daemon_handoff(",
    "authenticated Android runtime environment restoration",
)
for required in (
    "fs::symlink_metadata(path)",
    "metadata.file_type().is_dir()",
    "metadata.uid() == expected_uid",
    "metadata.gid() == required_group",
    "fs::canonicalize(path)",
    'process_ids("zygote64")',
    'fs::read_to_string(proc_path.join("status"))',
    'ids.split_whitespace().eq(["0", "0", "0", "0"])',
    'b"u:r:zygote:s0\\0"',
    'cmdline.split(|byte| *byte == 0).next() == Some(b"zygote64".as_slice())',
    'fs::metadata("/system/bin/app_process64")',
    "expected_exe.dev() == process_exe.dev()",
    "expected_exe.ino() == process_exe.ino()",
    'fs::read(proc_path.join("environ"))',
    "bytes.last() == Some(&0)",
    "selected.len() == ANDROID_RUNTIME_CLASSPATHS.len()",
    'entry.starts_with("/system/") || entry.starts_with("/apex/")',
    "fs::canonicalize(path)",
    "metadata.file_type().is_file()",
    "std::env::remove_var(name)",
    "std::env::set_var(name, path)",
    "std::env::set_var(name, value)",
):
    if required not in runtime_restore:
        raise SystemExit(f"Android runtime environment restoration omits {required} in {path}")
for forbidden in (
    "PID1_ENVIRON_PATH",
    'std::env::var("BOOTCLASSPATH")',
    "return Ok(Vec::new())",
):
    if forbidden in runtime_restore:
        raise SystemExit(f"untrusted/optional Android runtime environment path survived in {path}: {forbidden}")
if source.count("restore_android_runtime_environment()") != 3:
    raise SystemExit(f"Android runtime restore helper must have one definition and two calls in {path}")

# The fixed lifecycle starts ordinary services while the current framework is
# alive, reserves Vector for one monitored launch, proves its root socket,
# supplies/observes one zygote boundary, then checks the official CLI. This is
# intentionally the reverse of the old "restart zygote then start services"
# flow which left lspd/provider rendezvous unavailable to the new zygote.
lifecycle, lifecycle_base = section(
    "fn run_module_service_lifecycle()",
    "fn activity_manager_ready()",
    "Vector/LSPosed lifecycle",
)
service_local = locate(
    r'run_stage_to_completion\(\s*"service"',
    "bounded service stage",
    lifecycle,
)
launch_local = locate(
    r"launch_vector_service_directly\(\)\?;",
    "monitored Vector service launch",
    lifecycle,
)
socket_local = locate(
    r"vector_socket_registered\(\)",
    "live Vector socket proof",
    lifecycle[launch_local:],
) + launch_local
zygote_local = locate(
    r"ensure_zygote_boundary_after_services\(&old_system_servers\)\?;",
    "zygote/system_server boundary",
    lifecycle,
)
cli_local = locate(
    r"verify_vector_framework_cli\(\)\?;",
    "Vector official CLI health proof",
    lifecycle,
)
if not service_local < launch_local < socket_local < zygote_local < cli_local:
    raise SystemExit(
        f"unsafe Vector/LSPosed lifecycle in {path}: expected service < monitored "
        "Vector launch < socket < zygote boundary < official CLI"
    )

run_inner, run_inner_base = section("fn run_inner(", "pub fn run(", "initial late-load")
initial_lifecycle = locate(
    r"run_module_service_lifecycle\(\)\?;",
    "initial module service lifecycle",
    run_inner,
)
initial_boot = locate(
    r'run_stage_to_completion\(\s*"boot-completed"',
    "initial bounded boot-completed stage",
    run_inner,
)
initial_receipt = locate(
    r"write_trusted_module_receipt\(&staged_daemon, &expected_daemon_sha256\)\?;",
    "trusted root-private module completion receipt",
    run_inner,
)
initial_manager = locate(
    r"restart_manager_after_late_load\(package_name\);",
    "post-lifecycle Manager refresh",
    run_inner,
)
if not initial_lifecycle < initial_boot < initial_receipt < initial_manager:
    raise SystemExit(
        f"unsafe initial late-load order in {path}: expected lifecycle < "
        "boot-completed < trusted receipt < Manager refresh"
    )
completion = run_inner_base + initial_receipt

retry, retry_base = section("pub fn retry_modules(", "fn dump_process_info(", "module retry")
retry_reset = locate(r"utils::reset_std\(\)", "module retry stdio reset", retry)
retry_runtime = locate(
    r"restore_android_runtime_environment\(\)",
    "module retry Android runtime restoration",
    retry,
)
retry_pre = locate(r"run_late_load_compat_stage\(\)", "retry pre-stage", retry)
retry_post = locate(r'run_stage_checked\("post-mount", true\)', "retry post-mount", retry)
retry_lifecycle = locate(r"run_module_service_lifecycle\(\)", "retry lifecycle", retry)
retry_boot = locate(
    r'run_stage_to_completion\(\s*"boot-completed"',
    "retry boot-completed",
    retry,
)
retry_private = locate(
    r"publish_private_receipt_exact\(&private_receipts, run_id, &receipt\)\?;",
    "retry private receipt",
    retry,
)
retry_public = locate(
    r"publish_public_receipt_exact\(&public_receipts, run_id, &receipt\)\?;",
    "retry public receipt",
    retry,
)
retry_manager = locate(
    r"restart_manager_after_late_load\(package_name\);",
    "retry Manager refresh",
    retry,
)
if not (
    retry_reset < retry_runtime < retry_pre < retry_post < retry_lifecycle < retry_boot < retry_private
    < retry_public < retry_manager
):
    raise SystemExit(
        f"unsafe module-retry order in {path}: expected reset < Android env < pre < post-mount < "
        "lifecycle < boot-completed < private receipt < public receipt < Manager"
    )

if len(re.findall(r'run_stage_to_completion\(\s*"service"', source)) != 1:
    raise SystemExit(f"service dispatch is not centralized in {path}")
if len(re.findall(r'run_stage_to_completion\(\s*"boot-completed"', source)) != 2:
    raise SystemExit(f"initial/retry boot-completed dispatch count is not two in {path}")

for required in (
    'require_vector_regular_file(&service_path, "service entrypoint")?;',
    'require_vector_regular_executable(&daemon_path, "daemon")?;',
    'require_vector_regular_executable(&cli_path, "CLI")?;',
    "RMOP_PAD3_VECTOR_SERVICE_V3",
    "exec /system/bin/unshare -m /system/bin/sh -c",
    "/system/bin/mount -o rslave none /",
    ".envs(crate::module::get_common_script_envs(Some(",
    "VECTOR_MODULE_ID,",
    'compact.contains("\\\"success\\\":true")',
    'output.contains("\\\"Framework Version\\\"")',
    "VectorServiceState::Running",
    "stop_stale_vector_launcher()?;",
    'argument == b"org.matrix.vector.daemon.VectorDaemon"',
    'Path::new("/proc").join(pid.to_string()).exists()',
    "stale Vector daemon owners did not exit within",
    "fs::symlink_metadata(VECTOR_SOCKET).is_ok()",
    "fn create_public_log_exact(",
    "libc::O_EXCL",
    "libc::O_NOFOLLOW",
    "libc::renameat(",
    'create_public_log_exact(VECTOR_SERVICE_LOG, "Vector service launcher log")',
    "let _ = child.kill();",
    "let _ = child.wait();",
    "launcher terminated; see",
    'Command::new("/system/bin/am")',
    '.arg("get-current-user")',
):
    if required not in source:
        raise SystemExit(f"missing Vector/LSPosed lifecycle guard in {path}: {required}")

stale_cleanup, _ = section(
    "fn process_has_known_vector_credentials(",
    "fn prepare_vector_service_stage(",
    "authenticated stale Vector cleanup",
)
for required in (
    'credentials("Uid:")',
    'credentials("Gid:")',
    'uids.as_slice() == ["0", "0", "0", "0"]',
    'uids.as_slice() == ["0", "1000", "0", "1000"]',
    'gids.as_slice() == ["0", "0", "0", "0"]',
    'fs::metadata(proc_path.join("cwd"))',
    'cwd.dev() != vector_directory.dev() || cwd.ino() != vector_directory.ino()',
    'comm == b"vectord\\n"',
    'argument == b"/data/adb/modules/zygisk_vector/daemon"',
    'argument == b"org.matrix.vector.daemon.VectorDaemon"',
    'format!("{VECTOR_DIR}/daemon.apk")',
    'fs::metadata(VECTOR_DIR)',
    'vector_directory.uid() == 0',
    'vector_directory.gid() == 0',
    'libc::kill(pid as libc::pid_t, libc::SIGKILL)',
    'error.raw_os_error() != Some(libc::ESRCH)',
    'Path::new("/proc").join(pid.to_string()).exists()',
):
    if required not in stale_cleanup:
        raise SystemExit(f"stale Vector cleanup omits {required} in {path}")
for forbidden in (
    'String::from_utf8_lossy(&cmdline).contains(',
    'fs::remove_file("/data/adb/lspd/lock")',
):
    if forbidden in stale_cleanup:
        raise SystemExit(f"unsafe stale Vector cleanup survived in {path}: {forbidden}")

vector_launch, _ = section(
    "fn launch_vector_service_directly(",
    "fn system_server_replaced(",
    "monitored Vector launcher",
)
for required in (
    "command.pre_exec(||",
    "utils::detach_process_group(true);",
    "utils::switch_cgroups();",
    ".try_wait()",
    "let _ = child.kill();",
    "let _ = child.wait();",
):
    if required not in vector_launch:
        raise SystemExit(f"monitored Vector launcher omits {required} in {path}")

vector_cli, _ = section(
    "fn verify_vector_framework_cli(",
    "fn run_module_service_lifecycle(",
    "bounded Vector CLI health check",
)
for required in (
    'create_public_log_exact(VECTOR_CLI_LOG, "Vector CLI log")',
    "let deadline = Instant::now() + timeout;",
    "std::cmp::min(deadline, Instant::now() + Duration::from_secs(3))",
    ".try_wait()",
    "let _ = child.kill();",
    "let _ = child.wait();",
    ".take(4097)",
    'compact.contains("\\\"success\\\":true")',
    'output.contains("\\\"Framework Version\\\"")',
):
    if required not in vector_cli:
        raise SystemExit(f"bounded Vector CLI health check omits {required} in {path}")
for forbidden in (".output()", "wait_with_output()", ".wait()?"):
    if forbidden in vector_cli:
        raise SystemExit(f"unbounded Vector CLI wait survived in {path}: {forbidden}")

regular_start = source.find("fn require_vector_regular_file(")
regular_end = source.find("fn vector_module_enabled(", regular_start)
if regular_start < 0 or regular_end <= regular_start:
    raise SystemExit(f"missing interpreted Vector service validator in {path}")
regular_body = source[regular_start:regular_end]
for required in (
    "fs::symlink_metadata(path)",
    "metadata.file_type().is_file()",
    "metadata.uid() == 0 && metadata.gid() == 0",
):
    if required not in regular_body:
        raise SystemExit(f"Vector service validator omits {required} in {path}")
for forbidden in ("permissions().mode()", "0o111"):
    if forbidden in regular_body:
        raise SystemExit(f"interpreted Vector service is executable-gated in {path}")

for forbidden in (
    "fn launch_vector_adapter(",
    "fn verify_vector_system_server_bridge(",
    "verify_vector_system_server_bridge(marker)",
    "mark_vector_verification_log()",
    "vector_adapter_requested()",
    "File::create(VECTOR_SERVICE_LOG)",
    ".create(true)\n        .append(true)\n        .open(MODULE_LIFECYCLE_LOG)",
):
    if forbidden in source:
        raise SystemExit(f"legacy Vector UI/logcat adapter survived in {path}: {forbidden}")

for required in (
    "pub fn retry_modules(",
    "require_exact_ksu_selinux_context()",
    "module retry requires SELinux enforcing=1",
    "RetryDaemonAuthority::pin(expected_ksud_sha256)",
    'File::open("/proc/self/exe")',
    "module-retry is not executing the installed /data/adb/ksud inode",
    "utils::switch_mnt_ns(1)",
    'utils::reset_std().context("failed to reset stdio after joining init mount namespace")',
    "verify_fresh_ksu_control()",
    "publish_private_receipt_exact(&private_receipts, run_id, &receipt)",
    "publish_public_receipt_exact(&public_receipts, run_id, &receipt)",
    "unlink_sync_prove_absent(",
):
    if required not in retry and required not in source:
        raise SystemExit(f"missing authenticated module-retry guard in {path}: {required}")

for required in (
    "ModuleRetry {",
    "run_id: String",
    "expected_ksud_sha256: String",
    "crate::late_load::retry_modules(",
):
    if required not in cli_source:
        raise SystemExit(f"missing module-retry CLI contract in {cli_path}: {required}")

for required in (
    "pub fn exec_script_until",
    "status.success()",
    "child.kill()",
    "child.wait()",
    "shared stage deadline",
):
    if required not in module_source:
        raise SystemExit(f"missing bounded script receipt in {module_path}: {required}")

for required in (
    "io::{ErrorKind, Write}",
    "Late-load compatibility treats an absent module root as an empty module set.",
    "Permission failures and other real I/O errors still abort the stage.",
    "Err(error) if error.kind() == ErrorKind::NotFound",
    "return Ok(());",
    "Err(error) => return Err(error.into())",
    "Err(error) if error.kind() == ErrorKind::NotFound => Vec::new()",
):
    if required not in module_source:
        raise SystemExit(f"missing absent-module-root guard in {module_path}: {required}")
for forbidden in (
    "let dir = std::fs::read_dir(modules_dir)?;",
    "std::fs::read_dir(defs::MODULE_DIR)?",
):
    if forbidden in module_source:
        raise SystemExit(f"strict absent-module-root read survived in {module_path}: {forbidden}")

for required in (
    "fn driver_fd() -> std::io::Result<RawFd>",
    "std::io::Error::from_raw_os_error(libc::ENODEV)",
    "let _ = DRIVER_FD.set(fd);",
    "fn query_info() -> std::io::Result<ksu_uapi::ksu_get_info_cmd>",
    "pub fn refresh_info() -> ksu_uapi::ksu_get_info_cmd",
    "let Ok(cmd) = query_info() else",
):
    if required not in ksucalls_source:
        raise SystemExit(f"missing fresh KernelSU control guard in {ksucalls_path}: {required}")
for forbidden in (
    "get_or_init(|| init_driver_fd().unwrap_or(-1))",
    "INFO_CACHE.get_or_init",
):
    if forbidden in ksucalls_source:
        raise SystemExit(f"stale KernelSU control cache survived in {ksucalls_path}: {forbidden}")

for required in (
    "let info = crate::ksucalls::refresh_info();",
    "crate::ksu_uapi::KSU_GET_INFO_FLAG_LATE_LOAD",
    "crate::ksu_uapi::KERNEL_SU_UAPI_VERSION",
    "KernelSU control info was unavailable after module load",
    "KernelSU uapi mismatch after module load",
    "KernelSU did not report late-load mode after module load",
):
    if required not in source:
        raise SystemExit(f"missing fresh post-load verification in {path}: {required}")

for required in (
    'const CLEANUP_ORIGINAL_KPTR_ENV: &str = "KSU_LATE_LOAD_CLEANUP_KPTR";',
    'const CLEANUP_MODULES_ENV: &str = "KSU_LATE_LOAD_CLEANUP_MODULES";',
    "const CLEAN_ABORT_EXIT_STATUS: i32 = 200;",
    "const CLEAN_SUCCESS_EXIT_STATUS: i32 = 201;",
    'const KSU_SELINUX_CONTEXT_BYTES: &[u8] = b"u:r:ksu:s0\\0";',
    "fn require_exact_ksu_selinux_context() -> Result<()>",
    'let domain = fs::read("/proc/self/attr/current")',
    "domain.as_slice() == KSU_SELINUX_CONTEXT_BYTES",
    "require_exact_ksu_selinux_context()?;",
    "libc::geteuid()",
    "libc::getegid()",
    "post-load cleanup daemon digest is not the staged build pin",
    "post-load cleanup module flag does not match the invocation",
    "capture_post_load_binding(",
    "CleanupAuthorities::pin_before_load(&staged_daemon, &expected_daemon_sha256)",
    "let expectation = cleanup_expectation.insert(",
    "expectation.module_loaded = true;",
    "validate_after_load()",
    "libc::fstatfs(file.as_raw_fd()",
    "PROC_SUPER_MAGIC",
    "SELINUX_MAGIC",
    "restore_kptr_restrict_exact(&mut authorities.kptr_restrict, expectation.original_kptr)",
    "&authorities.private_receipts",
    "&authorities.public_receipts",
    "remove_private_run_exact(authorities)",
    'match (installed.nlink(), private.nlink(), exec_name)',
    '(2, 2, Some(path))',
    '(1, 1, None)',
    "verify_installed_daemon_exact(",
    "verify_current_path_identities(authorities)",
    "current /data/adb mount does not match the retained finalization authority",
    "current private late-load root does not match the retained authority",
    "current /data/adb/ksud does not name the retained installed inode",
    "installed /data/adb/ksud metadata/inode is not exact root:root 0755 nlink=1",
    "installed daemon SHA-256 failed exact post-cleanup verification",
    "verify_fresh_ksu_control()",
    "KSU_GET_INFO_FLAG_LKM",
    "KSU_GET_INFO_FLAG_LATE_LOAD",
    "verify_receipt_exact(",
    "publish_public_receipt_exact(&authorities.public_receipts, run_id, content)",
    "require_original_kptr_exact(&mut authorities.kptr_restrict, expectation.original_kptr)",
    "require_enforcing_exact(&mut authorities.selinux_enforce)",
    "metadata.uid() == 2000",
    "metadata.gid() == 2000",
    "metadata.mode() & 0o777 == 0o771",
    "path_identity.dev() == directory_identity.dev()",
    "path_identity.ino() == directory_identity.ino()",
    "cleanup_post_load_failure(&mut expectation)",
    "std::process::exit(CLEAN_ABORT_EXIT_STATUS);",
    "std::process::exit(CLEAN_SUCCESS_EXIT_STATUS);",
    "retained-fd success finalization exact",
    "Panic=abort and signals never reach",
):
    if required not in source:
        raise SystemExit(f"missing authenticated ksu cleanup guard in {path}: {required}")

context_helper = source.find("fn require_exact_ksu_selinux_context()")
executor_validator = source.find("fn validate_post_load_executor(", context_helper)
validator_end = source.find("fn unlink_same_inode_or_absent(", executor_validator)
if not (context_helper >= 0 and executor_validator > context_helper and validator_end > executor_validator):
    raise SystemExit(f"exact SELinux context validator ordering is missing in {path}")
context_helper_source = source[context_helper:executor_validator]
executor_validator_source = source[executor_validator:validator_end]
for forbidden in (
    "read_to_string",
    ".trim(",
    "trim_matches",
    "strip_suffix",
    "ends_with",
):
    if forbidden in context_helper_source or forbidden in executor_validator_source:
        raise SystemExit(
            f"lossy SELinux context normalization survived in {path}: {forbidden}"
        )
if source.count('const KSU_SELINUX_CONTEXT_BYTES: &[u8] = b"u:r:ksu:s0\\0";') != 1:
    raise SystemExit(f"exact NUL-terminated KSU context constant is not unique in {path}")
context_call = executor_validator_source.find("require_exact_ksu_selinux_context()?;")
identity_check = executor_validator_source.find("libc::geteuid()")
if not (context_call >= 0 and identity_check > context_call):
    raise SystemExit(f"SELinux context bytes are not authenticated before uid/gid in {path}")
for forbidden in (
    'let domain = fs::read_to_string("/proc/self/attr/current")',
    'domain.trim() == "u:r:ksu:s0"',
):
    if forbidden in source:
        raise SystemExit(f"text-normalized SELinux context check survived in {path}: {forbidden}")

if source.count("std::process::exit(CLEAN_ABORT_EXIT_STATUS);") != 1:
    raise SystemExit(f"reserved cleanup exit is not unique in {path}")
if source.count("std::process::exit(CLEAN_SUCCESS_EXIT_STATUS);") != 1:
    raise SystemExit(f"reserved success exit is not unique in {path}")
load_module = source.find("ksuinit::load_module(&ko_data, params)")
authority_pin = source.find("CleanupAuthorities::pin_before_load(")
cleanup_expected = source.find("let expectation = cleanup_expectation.insert(", authority_pin)
module_loaded = source.find("expectation.module_loaded = true;", load_module)
fresh_control = source.find("let info = crate::ksucalls::refresh_info();", module_loaded)
explicit_cleanup = source.find("cleanup_post_load_failure(&mut expectation)", completion)
success_finalize = source.find("finalize_post_load_success(&mut expectation)", completion)
success_exit = source.find("std::process::exit(CLEAN_SUCCESS_EXIT_STATUS);", success_finalize)
if not (
    authority_pin >= 0
    and cleanup_expected > authority_pin
    and load_module > cleanup_expected
    and module_loaded > load_module
    and fresh_control > module_loaded
    and completion > fresh_control
    and success_finalize > completion
    and success_exit > success_finalize
    and explicit_cleanup > success_finalize
):
    raise SystemExit(
        f"unsafe finalization lifetime in {path}: expected retained authority "
        "pins < expectation publication < load_module < infallible loaded bit < "
        "fresh control < trusted receipt < success finalizer < reserved 201"
    )
run_wrapper = source[source.find("pub fn run("):]
if re.search(r"Ok\(\(\)\)\s*=>\s*Ok\(\(\)\)", run_wrapper):
    raise SystemExit(f"generic exit-0 success path survived in {path}")
if "impl Drop for PostLoadCleanup" in source:
    raise SystemExit(
        f"post-load cleanup incorrectly depends on Drop in {path}"
    )

for required in (
    "let stage_deadline =",
    "exec_common_scripts_until",
    "exec_stage_script_until",
    "exec_stage_script_except_until",
):
    if required not in init_event_source:
        raise SystemExit(
            f"missing shared stage-wide deadline in {init_event_path}: {required}"
        )

for required in (
    '"KSU_LATE_LOAD_STAGED_DAEMON"',
    '"KSU_LATE_LOAD_STAGED_SHA256"',
    '"KSU_LATE_LOAD_RUN_ID"',
    "utils::stage_daemon_from(&staged_daemon, &expected_daemon_sha256)",
    '"/data/adb/.rmop-late-load/modules-loaded"',
    'enforcing.as_slice() == b"1" || enforcing.as_slice() == b"1\\n"',
    '"version=1\\nboot_id={boot_id}\\nrun_id={run_id}\\nksud_sha256={expected_daemon_sha256}\\n"',
    "run_id.len() == 32",
    ".create_new(true)",
    "libc::O_CLOEXEC | libc::O_NOFOLLOW",
    "validate_receipt_file(&published, 0o600",
    "validate_private_receipt_directory()?;",
    "clear_module_completion_receipts()?;",
):
    if required not in source:
        raise SystemExit(f"missing trusted helper handoff in {path}: {required}")

if "/data/local/tmp/.ksud-stage" in source or "/data/local/tmp/.ksud-stage" in utils_source:
    raise SystemExit("public fixed ksud stage path survived the device patch set")

for required in (
    'const PRIVATE_LATE_LOAD_ROOT: &str = "/data/adb/.rmop-late-load";',
    "OFlags::NOFOLLOW",
    "metadata.uid() == 0 && metadata.gid() == 0",
    "trusted stage SHA-256 mismatch",
    "installed daemon SHA-256 mismatch after rename",
    "installed daemon is not the inode renamed from the trusted stage",
):
    if required not in utils_source:
        raise SystemExit(f"missing race-safe staged daemon receipt in {utils_path}: {required}")
if utils_source.count("OFlags::NOFOLLOW") < 2:
    raise SystemExit(f"source/destination O_NOFOLLOW checks are incomplete in {utils_path}")

for required in (
    '"KSU_LATE_LOAD_RUN_ID"',
    '".ksu-late-load-modules-ok"',
    "(verify_st.st_mode & 0777) == 0644",
    "(st.st_mode & 0777) == 0600",
    "modules and run-id=<32-lowercase-hex> are required together",
    "KSU_LATE_LOAD_CLEAN_SUCCESS_EXIT 201",
    "LATE_LOAD_STATUS_KSU_CLEAN_SUCCESS 24",
    "refused generic ksud success without retained-fd finalization proof",
    "atomic_int ksu_success_proven",
    "late_load_request_watcher_proof(",
    "late_load_proven_success_fail_stop()",
    "Normalize only after the watcher acknowledged the authenticated proof",
):
    if required not in helper_source:
        raise SystemExit(f"missing nonce-bound helper receipt in {helper_path}: {required}")

cleanup_setter = "atomic_store_explicit(&mailbox->ksu_cleanup_proven, 1"
success_setter = "atomic_store_explicit(&mailbox->ksu_success_proven, 1"
if helper_source.count(cleanup_setter) != 1:
    raise SystemExit(f"authenticated cleanup mailbox setter is not unique in {helper_path}")
if helper_source.count(success_setter) != 1:
    raise SystemExit(f"authenticated success mailbox setter is not unique in {helper_path}")
cleanup_wait = helper_source.find("status = wait_loader_status(loader")
cleanup_set = helper_source.find(cleanup_setter, cleanup_wait)
success_set = helper_source.find(success_setter, cleanup_wait)
cleanup_parent = helper_source.find("parent_cleanup:", max(cleanup_set, success_set))
cleanup_proof = helper_source.find("int ksu_cleanup_proven =", cleanup_parent)
success_proof = helper_source.find("int ksu_success_proven =", cleanup_parent)
cleanup_finish = helper_source.find("late_load_finish_watcher(", cleanup_proof)
cleanup_verified = helper_source.find(
    "verified_ksu_cleanup_handoff =", cleanup_finish
)
success_verified = helper_source.find(
    "verified_ksu_success_handoff =", cleanup_finish
)
cleanup_fail_stop = helper_source.find(
    "late_load_parent_fail_stop_cleanup(", cleanup_verified
)
if not (
    cleanup_wait >= 0
    and cleanup_set > cleanup_wait
    and success_set > cleanup_wait
    and cleanup_parent > max(cleanup_set, success_set)
    and cleanup_proof > cleanup_parent
    and success_proof > cleanup_parent
    and cleanup_finish > cleanup_proof
    and cleanup_verified > cleanup_finish
    and success_verified > cleanup_finish
    and cleanup_fail_stop > cleanup_verified
):
    raise SystemExit(
        f"unsafe authenticated proof handoff order in {helper_path}: expected "
        "wait exact loader < unique 200/201 setters < exact parent pairs < "
        "proof watcher join < verified handoff < fallback fail-stop"
    )

for required in (
    "if (restore_kptr && !ksu_success_proven && !ksu_cleanup_proven &&",
    "!ksu_success_proven && !ksu_cleanup_proven)",
    "if (!ksu_success_proven && !ksu_cleanup_proven) {\n    cleanup_private_stage(&staged);",
    "int ksu_handoff_proven = ksu_success_proven || ksu_cleanup_proven;",
    "if (!ksu_handoff_proven && parent_kptr_was >= 0 &&",
    "ksu_handoff_proven\n          ? 1",
):
    if required not in helper_source:
        raise SystemExit(f"missing proof-gated post-enforce skip in {helper_path}: {required}")

watch_abort = helper_source.find("static void late_load_watch_abort_cleanup")
watch_fast = helper_source.find("ksu_success_proven != ksu_cleanup_proven", watch_abort)
watch_kptr = helper_source.find("set_kptr_restrict_checked(mailbox->original_kptr", watch_abort)
if not (watch_abort >= 0 and watch_fast > watch_abort and watch_kptr > watch_fast):
    raise SystemExit(f"watcher proof fast path does not precede forbidden reopen in {helper_path}")

exit201 = helper_source.find("exit_status == KSU_LATE_LOAD_CLEAN_SUCCESS_EXIT")
exit0_reject = helper_source.find("if (exit_status == 0)", exit201)
exit200 = helper_source.find("exit_status == KSU_LATE_LOAD_CLEAN_ABORT_EXIT", exit0_reject)
if not (exit201 >= 0 and exit0_reject > exit201 and exit200 > exit0_reject):
    raise SystemExit(f"reserved 201/exit0 rejection/200 classifier order is unsafe in {helper_path}")

parent_cleanup = helper_source.find("parent_cleanup:")
parent_receipt_rollback_match = re.search(
    r"if\s*\([^)]*enable_modules[^)]*status\s*!=\s*LATE_LOAD_STATUS_OK[^)]*\)"
    r"\s*\{\s*parent_receipts_clean\s*=\s*invalidate_module_receipts_exact",
    helper_source[parent_cleanup:],
    re.DOTALL,
)
parent_receipt_rollback = (
    parent_cleanup + parent_receipt_rollback_match.start()
    if parent_receipt_rollback_match is not None
    else -1
)
parent_selinux_watchdog = helper_source.find(
    "ensure_enforcing_one_after_worker(request->stderr_fd)", parent_cleanup
)
parent_final_receipt_rollback = helper_source.find(
    "invalidate_module_receipts_exact(request->stderr_fd)",
    parent_selinux_watchdog,
)
parent_watcher_finish = helper_source.find(
    "late_load_finish_watcher(", parent_final_receipt_rollback
)
parent_fail_stop = helper_source.find(
    "late_load_parent_fail_stop_cleanup(", parent_watcher_finish
)
parent_lock_release = helper_source.find("close(lock_fd);", parent_fail_stop)
if not (
    parent_cleanup >= 0
    and parent_receipt_rollback > parent_cleanup
    and parent_selinux_watchdog > parent_receipt_rollback
    and parent_final_receipt_rollback > parent_selinux_watchdog
    and parent_watcher_finish > parent_final_receipt_rollback
    and parent_fail_stop > parent_watcher_finish
    and parent_lock_release > parent_fail_stop
):
    raise SystemExit(
        f"unsafe parent rollback order in {helper_path}: expected private/public "
        "receipt invalidation before and after the SELinux enforcing watchdog, "
        "then watcher finalization and fail-stop cleanup before lock release"
    )
PY

HELPER_SOURCE="$ROOT/src/payloads/su_daemon/late_load.c"
for required in \
  '#ifndef RMOP_EXPECTED_KSUD_SHA256' \
  '#define PRIVATE_STAGE_ROOT "/data/adb/.rmop-late-load"' \
  '"KSU_LATE_LOAD_STAGED_DAEMON"' \
  '"KSU_LATE_LOAD_STAGED_SHA256"' \
  '"KSU_LATE_LOAD_RUN_ID"' \
  '"KSU_LATE_LOAD_CLEANUP_KPTR"' \
  '"KSU_LATE_LOAD_CLEANUP_MODULES"' \
  'decode_expected_ksud_digest(expected)' \
  'memcmp(source_before, expected' \
  'sha256_fd(source, source_after)' \
  'sha256_fd(private_exec, private_digest)' \
  'mount(staged.exec_path, LOGCAT_PATH' \
  'setenv(KSU_STAGE_PATH_ENV, staged.stage_path' \
  'trusted_module_receipt_absent_exact' \
  'public_module_receipt_absent_exact' \
  'invalidate_module_receipts_exact' \
  'wait_late_load_worker(pid, worker_pidfd, request->stderr_fd)' \
  'ensure_enforcing_one_after_worker(request->stderr_fd)' \
  'LATE_LOAD_WATCHER_TIMEOUT_SECONDS' \
  'MAP_SHARED | MAP_ANONYMOUS' \
  'late_load_open_trusted_pidfd' \
  'late_load_watch_abort_cleanup' \
  'KSU_LATE_LOAD_CLEAN_ABORT_EXIT' \
  'KSU_LATE_LOAD_CLEAN_SUCCESS_EXIT' \
  'LATE_LOAD_STATUS_KSU_CLEAN_ABORT' \
  'LATE_LOAD_STATUS_KSU_CLEAN_SUCCESS' \
  'cleanup_handoff_expected' \
  'atomic_int ksu_cleanup_proven' \
  'atomic_int ksu_success_proven' \
  'Unique setter: it follows an empty exec-error pipe' \
  'Unique setter: reserved exit 201 follows the empty exec-error pipe' \
  'verified_ksu_cleanup_handoff' \
  'verified_ksu_success_handoff' \
  'late_load_worker_bootstrap' \
  'late_load_parent_fail_stop_cleanup' \
  'late_load_proven_success_fail_stop' \
  'late_load_request_watcher_proof' \
  'refused generic ksud success without retained-fd finalization proof' \
  'late_load_wait_final_watcher' \
  'fail-stop cleanup incomplete; retaining lock and retrying' \
  'Even an already-absent name needs a successful directory fsync' \
  'LATE_LOAD_WATCH_PREPARE' \
  'LATE_LOAD_WATCH_FINAL' \
  'late_load_finish_watcher' \
  'st.st_ino == staged->inode' \
  'late-load: root-private ksud verified'; do
  grep -Fq "$required" "$HELPER_SOURCE" || {
    echo "missing trusted helper handoff marker in $HELPER_SOURCE: $required" >&2
    exit 4
  }
done
LATE_LOAD_WATCH_PROBE="$ROOT/diagnostics/oneplus-pad3/late-load-watcher-probe.c"
for required in \
  'late_load_parent_death=%s' \
  'late_load_timeout=%s' \
  'late_load_lock_cleanup=%s' \
  'late_load_nominal_ok_parent_restore=%s' \
  'late_load_receipt_unlink_fail_stop=%s' \
  'late_load_receipt_open_fail_stop=%s' \
  'late_load_receipt_fsync_fail_stop=%s' \
  'late_load_receipt_io_fail_stop=%s' \
  'SYS_pidfd_open' \
  'kill(-mailbox->worker_pid, SIGKILL)'; do
  grep -Fq "$required" "$LATE_LOAD_WATCH_PROBE" || {
    echo "missing late-load parent-death/timeout diagnostic in $LATE_LOAD_WATCH_PROBE: $required" >&2
    exit 4
  }
done
KSU_CLEANUP_PROBE="$ROOT/diagnostics/oneplus-pad3/ksu-cleanup-handoff-probe.c"
for required in \
  'ksu_cleanup_exact_handoff=%s' \
  'ksu_success_exact_handoff=%s' \
  'ksu_success_exit0_rejected=%s' \
  'ksu_cleanup_fault_rejections=%s' \
  'ksu_success_fault_rejections=%s' \
  'ksu_success_partial_abort_reentry=%s' \
  'ksu_status_proof_mismatch_rejections=%s' \
  'ksu_success_watcher_delayed_ack=%s' \
  'ksu_success_watcher_bad_ack_fail_stop=%s' \
  'ksu_cleanup_panic_abort_false_proof=%s' \
  'ksu_selinux_context_exact_bytes=%s' \
  'PROBE_RESERVED_CLEAN_EXIT = 200' \
  'PROBE_RESERVED_SUCCESS_EXIT = 201' \
  'SUCCESS_INSTALLED_METADATA' \
  'SUCCESS_INSTALLED_HASH' \
  'SUCCESS_CURRENT_PATHS' \
  'SUCCESS_KSU_LATE_LOAD' \
  'SUCCESS_PUBLIC_RECEIPT' \
  'SUCCESS_KPTR_ORIGINAL' \
  'exact_ksu_selinux_context_bytes' \
  'sizeof(exact) - 1' \
  'newline[] = "u:r:ksu:s0\n"' \
  'double_nul[] = "u:r:ksu:s0\0"' \
  'suffix[] = "u:r:ksu:s0\0suffix"' \
  'memcmp(context, expected, sizeof(expected)) == 0' \
  'cleanup_private_run_model' \
  'waited_loader != expected_loader' \
  'exec_error_bytes != 0' \
  '!cleanup_handoff_expected' \
  'atomic_store_explicit(&mailbox->cleanup_proven' \
  'atomic_store_explicit(&mailbox->success_proven'; do
  grep -Fq "$required" "$KSU_CLEANUP_PROBE" || {
    echo "missing authenticated cleanup diagnostic in $KSU_CLEANUP_PROBE: $required" >&2
    exit 4
  }
done
KSU_CLEANUP_PROBE_BIN="$WORK/ksu-cleanup-handoff-probe"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$KSU_CLEANUP_PROBE" -o "$KSU_CLEANUP_PROBE_BIN"
"$KSU_CLEANUP_PROBE_BIN"
if grep -Fq '/data/local/tmp/.ksud-stage' "$HELPER_SOURCE"; then
  echo "public fixed ksud stage path survived in $HELPER_SOURCE" >&2
  exit 4
fi
grep -Fq '$(HELPER_EXTRA_CFLAGS)' "$ROOT/Makefile" || {
  echo "root helper build does not consume HELPER_EXTRA_CFLAGS" >&2
  exit 4
}
ROOT_UMH_SOURCE="$ROOT/src/payloads/CVE-2026-43499/core66/root.c"
for required in \
  '#ifndef RMOP_EXPECTED_ROOT_HELPER_SHA256' \
  'MFD_ALLOW_SEALING | MFD_EXEC' \
  'F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_EXEC' \
  '"/proc/%ld/fd/%d"' \
  'root_sha256_fd(memfd, sealed_digest)' \
  'prepare_android_root_helper(void)'; do
  grep -Fq "$required" "$ROOT_UMH_SOURCE" || {
    echo "missing sealed root-helper contract in $ROOT_UMH_SOURCE: $required" >&2
    exit 4
  }
done
grep -Fq '$(PAYLOAD_EXTRA_CFLAGS)' "$ROOT/Makefile" || {
  echo "payload build does not consume PAYLOAD_EXTRA_CFLAGS" >&2
  exit 4
}

echo "==> build $KMI kernelsu.ko for $KERNEL_RELEASE"
docker pull "$DDK_IMAGE" >/dev/null
docker run --rm \
  -v "$ROOT:/workspace" -w /workspace \
  -e KERNEL_RELEASE="$KERNEL_RELEASE" \
  -e TARGET_CONFIG='' \
  -e KSU_MANAGER_PACKAGE="$MANAGER_PACKAGE" \
  -e KSU_EXPECTED_SIZE="$MANAGER_CERT_SIZE" \
  -e KSU_EXPECTED_HASH="$MANAGER_CERT_HASH" \
  "$DDK_IMAGE" \
  bash /workspace/tools/kernel/build-ddk-module.sh "/workspace/build/oneplus-pad3-fixed/KernelSU"
docker run --rm -v "$KSU_WORK:/ksu" "$DDK_IMAGE" \
  chown -R "$(id -u):$(id -g)" /ksu

MODULE="$KSU_WORK/kernel/kernelsu.ko"
[ -s "$MODULE" ] || { echo "KernelSU module was not produced: $MODULE" >&2; exit 4; }
"$TOOLCHAIN/bin/llvm-strip" -d "$MODULE"
if [ "$HAVE_EXACT_GENERATED_PROFILE" -eq 1 ]; then
  python3 "$ROOT/src/kernelsu/tools/audit_module_against_target.py" \
    "$MODULE" \
    "$GENERATED_PROFILE_DIR/vmlinux" \
    "$GENERATED_PROFILE_DIR/Module.symvers" \
    --manual-relocation
else
  echo "[WARN] skipping module-vs-exact-target symbol audit because the local generated analysis bundle is absent." >&2
fi
grep -aq "$KERNEL_RELEASE" "$MODULE" || {
  echo "kernelsu.ko does not contain the exact release $KERNEL_RELEASE" >&2
  exit 4
}
MODULE_HASH=$(sha256sum "$MODULE" | awk '{print $1}')
mkdir -p "$KSU_WORK/userspace/ksud/bin/aarch64"
cp "$MODULE" "$KSU_WORK/userspace/ksud/bin/aarch64/${KMI}_kernelsu.ko"

echo "==> build ksud with the exact embedded module"
rustup target add aarch64-linux-android
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$TOOLCHAIN/bin/aarch64-linux-android35-clang"
export CC_aarch64_linux_android="$TOOLCHAIN/bin/aarch64-linux-android35-clang"
export AR_aarch64_linux_android="$TOOLCHAIN/bin/llvm-ar"
export LIBCLANG_PATH="$TOOLCHAIN/lib"
export BINDGEN_EXTRA_CLANG_ARGS_aarch64_linux_android="--target=aarch64-linux-android35 --sysroot=$TOOLCHAIN/sysroot"
# Prevent Cargo/rustc from embedding the builder's username and checkout path.
unset RUSTFLAGS
export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$HOME=/build/home"$'\x1f'"--remap-path-prefix=$KSU_WORK=/build/KernelSU"
cargo build --release --target aarch64-linux-android -p ksud \
  --manifest-path "$KSU_WORK/Cargo.toml"
KSUD="$WORK/ksud-oneplus-pad3"
cp "$KSU_WORK/target/aarch64-linux-android/release/ksud" "$KSUD"
if grep -aFq "$HOME/" "$KSUD"; then
  echo "built ksud still contains the builder home path" >&2
  exit 4
fi
for marker in \
  'KernelSU live:' \
  'late-load compatibility' \
  'failed to rejoin init mount namespace for module stages'; do
  grep -aq "$marker" "$KSUD" || {
    echo "built ksud is missing required common-patch marker: $marker" >&2
    exit 4
  }
done
if [ "${#device_patches[@]}" -gt 0 ]; then
  for marker in \
    'OnePlus Pad 3 late-load: replacement system_server verified' \
    'OnePlus Pad 3 late-load: installed monitored Vector service launcher with absolute Android tools' \
    'OnePlus Pad 3 late-load: monitored Vector service launched pid=' \
    'OnePlus Pad 3 late-load: live /data/adb/lspd/.cli_sock registration verified' \
    'OnePlus Pad 3 late-load: Vector CLI framework health verified' \
    'OnePlus Pad 3 late-load: service and boot-completed receipts verified; enforcing trusted completion commit' \
    'OnePlus Pad 3 late-load: trusted root-private completion receipt committed after SELinux enforcing readback' \
    'OnePlus Pad 3 module-retry: authenticated enforcing-state lifecycle started' \
    'OnePlus Pad 3 module-retry: lifecycle and receipts verified' \
    'KernelSU Manager restarted after module lifecycle' \
    'RMOP_PAD3_VECTOR_SERVICE_V3' \
    'failed to create secure public log temporary file' \
    'launcher terminated; see' \
    'stale Vector daemon owners did not exit within' \
    'trusted staged-daemon path was not supplied by the late-load helper' \
    'trusted stage SHA-256 mismatch' \
    'installed daemon SHA-256 mismatch after rename' \
    'KernelSU control info was unavailable after module load' \
    'KernelSU uapi mismatch after module load' \
    'KernelSU did not report late-load mode after module load' \
    'post-load cleanup executor SELinux context bytes are not exact u:r:ksu:s0 NUL-terminated form' \
    'retained-fd success finalization exact' \
    'emitting authenticated retained-fd success proof' \
    'installed /data/adb/ksud metadata/inode is not exact root:root 0755 nlink=1' \
    'installed daemon SHA-256 failed exact post-cleanup verification' \
    'current /data/adb mount does not match the retained finalization authority' \
    'current private late-load root does not match the retained authority' \
    'current /data/adb/ksud does not name the retained installed inode' \
    'final KernelSU control flags lack LKM+late-load' \
    'trusted completion receipt' \
    'failed to atomically publish public receipt' \
    'kptr_restrict did not retain the captured original value' \
    'SELinux was not exact enforcing=1 during success finalization' \
    'private executable cleanup state is not exact or idempotent' \
    'failed to pin pre-load cleanup authorities' \
    'failed to execute module late-load compatibility scripts'; do
    grep -aq "$marker" "$KSUD" || {
      echo "built ksud is missing required Pad 3 device-patch marker: $marker" >&2
      exit 4
    }
  done
fi
KSUD_HASH=$(sha256sum "$KSUD" | awk '{print $1}')
case "$KSUD_HASH" in
  ''|*[!0-9a-f]*) echo "invalid ksud SHA-256: $KSUD_HASH" >&2; exit 4 ;;
esac
[ "${#KSUD_HASH}" -eq 64 ] || {
  echo "invalid ksud SHA-256 length: ${#KSUD_HASH}" >&2
  exit 4
}

echo "==> build and securely repack signer-matched Root My Device KSU Manager"
MANAGER_BUILD_STARTED_NS=$(python3 -c 'import time; print(time.time_ns())')
MANAGER_VERSION_NAME=$(git -C "$KSU_WORK" describe --tags --always)
(
  export ORG_GRADLE_PROJECT_KEYSTORE_FILE="$RMOP_KEYSTORE"
  export ORG_GRADLE_PROJECT_KEYSTORE_PASSWORD="$RMOP_STORE_PASSWORD"
  export ORG_GRADLE_PROJECT_KEY_ALIAS="$RMOP_KEY_ALIAS"
  export ORG_GRADLE_PROJECT_KEY_PASSWORD="$RMOP_KEY_PASSWORD"
  cd "$KSU_WORK/manager"
  ./gradlew --no-daemon --no-configuration-cache clean :app:assembleRelease \
    -PKSU_PACKAGE_NAME="$MANAGER_PACKAGE" -PKSU_NAME="$MANAGER_NAME"
)

MANAGER_OUTPUT_DIR="$KSU_WORK/manager/app/build/outputs/apk/release"
MANAGER_METADATA="$MANAGER_OUTPUT_DIR/output-metadata.json"
MANAGER_INPUT=$(
  python3 - \
    "$MANAGER_METADATA" \
    "$MANAGER_OUTPUT_DIR" \
    "$MANAGER_PACKAGE" \
    "$KSU_VERSION" \
    "$MANAGER_VERSION_NAME" \
    "$MANAGER_BUILD_STARTED_NS" <<'PY'
import json
import stat
import sys
from pathlib import Path

metadata, output_dir = map(Path, sys.argv[1:3])
expected_package = sys.argv[3]
expected_version_code = int(sys.argv[4])
expected_version_name = sys.argv[5]
build_started_ns = int(sys.argv[6])


def fail(message: str) -> None:
    raise SystemExit(f"invalid Manager release output: {message}")


def require_current_regular(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        fail(f"{label} was not produced: {path}")
    if not stat.S_ISREG(info.st_mode):
        fail(f"{label} is not a regular non-symlink file: {path}")
    if info.st_size <= 0:
        fail(f"{label} is empty: {path}")
    if info.st_mtime_ns < build_started_ns:
        fail(f"{label} predates this Gradle build: {path}")


try:
    output_dir_info = output_dir.lstat()
except FileNotFoundError:
    fail(f"release output directory was not produced: {output_dir}")
if not stat.S_ISDIR(output_dir_info.st_mode):
    fail(f"release output directory is not a non-symlink directory: {output_dir}")

require_current_regular(metadata, "output metadata")
try:
    document = json.loads(metadata.read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as error:
    fail(f"cannot read output metadata {metadata}: {error}")

if document.get("applicationId") != expected_package:
    fail("metadata applicationId does not match the pinned Manager package")
if document.get("variantName") != "release":
    fail("metadata variantName is not release")
artifact_type = document.get("artifactType")
if artifact_type != {"type": "APK", "kind": "Directory"}:
    fail("metadata artifactType is not an APK directory")
elements = document.get("elements")
if not isinstance(elements, list) or len(elements) != 1:
    fail("metadata must describe exactly one release APK")
element = elements[0]
if not isinstance(element, dict):
    fail("metadata release element is not an object")
if element.get("type") != "SINGLE" or element.get("filters") != []:
    fail("metadata release element is not one unfiltered APK")
if element.get("versionCode") != expected_version_code:
    fail("metadata versionCode does not match the pinned KernelSU revision")
if element.get("versionName") != expected_version_name:
    fail("metadata versionName does not match the pinned KernelSU revision")

expected_filename = (
    f"KernelSU_{expected_version_name}_{expected_version_code}-release.apk"
)
output_filename = element.get("outputFile")
if output_filename != expected_filename:
    fail(f"metadata outputFile is not the intended release APK: {output_filename!r}")
if Path(output_filename).name != output_filename:
    fail("metadata outputFile is not a plain filename")

apk = output_dir / output_filename
require_current_regular(apk, "release APK")
print(apk)
PY
)
MANAGER_DIST="$WORK/manager-dist"
MANAGER_UNSIGNED="$MANAGER_DIST/RootMyDeviceKSU_${KSU_VERSION}_OnePlusPad3-unsigned.apk"
MANAGER_ALIGNED="$MANAGER_DIST/RootMyDeviceKSU_${KSU_VERSION}_OnePlusPad3-aligned.apk"
MANAGER_APK="$MANAGER_DIST/RootMyDeviceKSU_${KSU_VERSION}_OnePlusPad3.apk"
mkdir -p "$MANAGER_DIST"
rm -f "$MANAGER_UNSIGNED" "$MANAGER_ALIGNED" "$MANAGER_APK"
python3 - "$MANAGER_INPUT" "$MANAGER_UNSIGNED" "$KSUD" <<'PY'
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

source, destination, ksud = map(Path, sys.argv[1:])
with ZipFile(source, "r") as zin, ZipFile(destination, "w") as zout:
    for info in zin.infolist():
        name = info.filename
        if name.startswith("META-INF/"):
            continue
        if name.startswith("lib/"):
            parts = name.split("/")
            if len(parts) >= 3 and parts[1] != "arm64-v8a":
                continue
        if name == "lib/arm64-v8a/libksud.so":
            continue
        data = zin.read(name)
        copied = ZipInfo(filename=name, date_time=info.date_time)
        copied.compress_type = info.compress_type
        copied.external_attr = info.external_attr
        copied.comment = info.comment
        copied.create_system = info.create_system
        copied.extra = info.extra
        zout.writestr(copied, data, compress_type=info.compress_type)
    entry = ZipInfo("lib/arm64-v8a/libksud.so")
    entry.compress_type = ZIP_DEFLATED
    entry.external_attr = 0o100755 << 16
    zout.writestr(entry, ksud.read_bytes(), compress_type=ZIP_DEFLATED)
PY
"$ZIPALIGN" -P 16 -f 4 "$MANAGER_UNSIGNED" "$MANAGER_ALIGNED"
RMOP_STORE_PASSWORD="$RMOP_STORE_PASSWORD" \
RMOP_KEY_PASSWORD="$RMOP_KEY_PASSWORD" \
"$APKSIGNER" sign \
  --v1-signing-enabled false \
  --v2-signing-enabled true \
  --v3-signing-enabled false \
  --v4-signing-enabled false \
  --ks "$RMOP_KEYSTORE" \
  --ks-key-alias "$RMOP_KEY_ALIAS" \
  --ks-pass env:RMOP_STORE_PASSWORD \
  --key-pass env:RMOP_KEY_PASSWORD \
  --out "$MANAGER_APK" \
  "$MANAGER_ALIGNED"
rm -f "$MANAGER_UNSIGNED" "$MANAGER_ALIGNED"

verify_apk() {
  apk=$1
  expected_package=$2
  label=$3
  [ -s "$apk" ] || { echo "$label APK not found: $apk" >&2; return 1; }
  signer_output=$("$APKSIGNER" verify --verbose --print-certs "$apk") || {
    echo "$label APK signature verification failed" >&2
    return 1
  }
  signer_count=$(
    printf '%s\n' "$signer_output" |
      sed -n 's/^Number of signers: //p'
  )
  [ "$signer_count" = 1 ] || {
    echo "$label signer count mismatch: $signer_count != 1" >&2
    return 1
  }
  certificate_hashes=$(
    printf '%s\n' "$signer_output" |
      sed -n \
        -e 's/^Signer #[0-9][0-9]* certificate SHA-256 digest: //p' \
        -e 's/^V[0-9][^ ]* Signer: certificate SHA-256 digest: //p' |
      tr -d ':' |
      tr '[:upper:]' '[:lower:]' |
      sort -u
  )
  certificate_hash_count=$(
    printf '%s\n' "$certificate_hashes" | awk 'NF { count++ } END { print count+0 }'
  )
  [ "$certificate_hash_count" -eq 1 ] || {
    echo "$label certificate hash count mismatch: $certificate_hash_count != 1" >&2
    return 1
  }
  certificate_hash=$certificate_hashes
  case "$certificate_hash" in
    ''|*[!0-9a-f]*)
      echo "$label certificate digest is not lowercase hex" >&2
      return 1
      ;;
  esac
  [ "${#certificate_hash}" -eq 64 ] || {
    echo "$label certificate digest length mismatch: ${#certificate_hash}" >&2
    return 1
  }
  [ "$certificate_hash" = "$MANAGER_CERT_HASH" ] || {
    echo "$label signer mismatch: $certificate_hash != $MANAGER_CERT_HASH" >&2
    return 1
  }
  package_name=$(
    "$AAPT" dump badging "$apk" |
      sed -n "s/^package: name='\([^']*\)'.*/\1/p"
  )
  [ "$package_name" = "$expected_package" ] || {
    echo "$label package mismatch: $package_name != $expected_package" >&2
    return 1
  }
}

verify_apk "$MANAGER_APK" "$MANAGER_PACKAGE" 'Manager'
embedded_ksud_hash=$(python3 - "$MANAGER_APK" <<'PY'
import hashlib
import sys
from zipfile import ZipFile

with ZipFile(sys.argv[1], "r") as apk:
    print(hashlib.sha256(apk.read("lib/arm64-v8a/libksud.so")).hexdigest())
PY
)
[ "$embedded_ksud_hash" = "$KSUD_HASH" ] || {
  echo "Manager carries a stale ksud: $embedded_ksud_hash != $KSUD_HASH" >&2
  exit 4
}

echo "==> build exact Pad 3 exploit and root helper"
grep -Fq '#ifndef RMOP_EXPECTED_KSUD_SHA256' \
  "$ROOT/src/payloads/su_daemon/late_load.c" || {
  echo "root helper does not fail closed without the pinned ksud digest" >&2
  exit 4
}
HELPER_KSUD_DEFINE="-DRMOP_EXPECTED_KSUD_SHA256=\\\"$KSUD_HASH\\\""
NATIVE="$ROOT/build/$TARGET_SLUG"
PAYLOAD="$NATIVE/cve-2026-43499-standalone"
HELPER="$NATIVE/cve-2026-43499-root"
HELPER_TARGET="build/$TARGET_SLUG/cve-2026-43499-root"

# The payload's Route A never executes the public helper inode. Build that
# helper first, pin its exact digest into every payload form, and only then let
# make build the exploit. Removing the payload outputs makes the flag change a
# real dependency rather than relying on command-line flags to invalidate an
# otherwise up-to-date target.
rm -f "$HELPER"
make -C "$ROOT" TARGET="$TARGET" CORE="$CORE" \
  "HELPER_EXTRA_CFLAGS=$HELPER_KSUD_DEFINE" "$HELPER_TARGET"
HELPER_HASH=$(sha256sum "$HELPER" | awk '{print $1}')
case "$HELPER_HASH" in
  ''|*[!0-9a-f]*) echo "invalid root helper SHA-256: $HELPER_HASH" >&2; exit 4 ;;
esac
[ "${#HELPER_HASH}" -eq 64 ] || {
  echo "invalid root helper SHA-256 length: ${#HELPER_HASH}" >&2
  exit 4
}
PAYLOAD_HELPER_DEFINE="-DRMOP_EXPECTED_ROOT_HELPER_SHA256=\\\"$HELPER_HASH\\\""
rm -f \
  "$NATIVE/cve-2026-43499" \
  "$NATIVE/cve-2026-43499-standalone" \
  "$NATIVE/cve-2026-43499-app.so" \
  "$NATIVE/cve-2026-43499-app.release.so"
make -C "$ROOT" TARGET="$TARGET" CORE="$CORE" \
  "HELPER_EXTRA_CFLAGS=$HELPER_KSUD_DEFINE" \
  "PAYLOAD_EXTRA_CFLAGS=$PAYLOAD_HELPER_DEFINE" all release
[ -s "$PAYLOAD" ] || { echo "payload not produced: $PAYLOAD" >&2; exit 4; }
[ -s "$HELPER" ] || { echo "root helper not produced: $HELPER" >&2; exit 4; }
python3 "$ROOT/tools/verify-pad3-reclaim-binary.py" \
  "$NATIVE/cve-2026-43499" \
  --objdump "$TOOLCHAIN/bin/llvm-objdump"
grep -aFq "$KSUD_HASH" "$HELPER" || {
  echo "root helper does not embed the exact pinned ksud digest: $KSUD_HASH" >&2
  exit 4
}
for pinned_payload in \
  "$NATIVE/cve-2026-43499" \
  "$NATIVE/cve-2026-43499-standalone" \
  "$NATIVE/cve-2026-43499-app.so" \
  "$NATIVE/cve-2026-43499-app.release.so"; do
  grep -aFq "$HELPER_HASH" "$pinned_payload" || {
    echo "payload does not embed the exact root helper digest: $pinned_payload" >&2
    exit 4
  }
  for uuid_marker in \
    'slide uuid-leaked nfulnl.name' \
    'slide restore uuid'; do
    grep -aFq "$uuid_marker" "$pinned_payload" || {
      echo "Pad 3 payload is missing the UUID slide marker '$uuid_marker': " \
           "$pinned_payload" >&2
      exit 4
    }
  done
  for mode4_marker in \
    'fops mode4 hybrid owner-safe' \
    'slide uuid forged erase pi-root empty' \
    'pipe prepare request accepted' \
    'kernel physical variables memstart=' \
    'kernel physical live check=' \
    'PIPE_PREPARE_NONFATAL' \
    'PIPE_MARKER_WRITE_NONFATAL' \
    'consumer quiesced seq' \
    'root A2 snapshot retry' \
    'root A3 snapshot retry' \
    'waiter PI cleanup cached' \
    'waiter PI cleanup exact' \
    'PI_CLEANUP_FAIL_STOP waiter parked' \
    'PI_CLEANUP_FAIL_STOP process leader parked' \
    'CFI_FAIL_STOP cleanup unknown' \
    'CFI_FAIL_STOP A3 commit result' \
    'kernel primitive dirty marker committed' \
    'dirty supervisor timeout no SIGKILL' \
    'CURRENT_BOOT_DIRTY_RETAIN timeout child=' \
    'CURRENT_BOOT_DIRTY_RETAIN waitpid attempt=' \
    'no kill/no retry' \
    'CURRENT_BOOT_DIRTY_RETAIN supervisor parked' \
    'exact target rejects runtime pselect layout overrides'; do
    grep -aFq "$mode4_marker" "$pinned_payload" || {
      echo "Pad 3 payload is missing the mode4/PI marker '$mode4_marker': " \
           "$pinned_payload" >&2
      exit 4
    }
  done
  for reclaim_marker in \
    'Pad3 slide KernelSnitch diagnostic accepted=' \
    'no-route-gate=1' \
    'Pad3 KernelSnitch waiter barrier ready=' \
    'KernelSnitch waiter pile incomplete; collision scan refused' \
    'Pad3 KernelSnitch leak child parked elapsed-ms=' \
    'Pad3 mm adjacency pins children=50/50 pins=50/50' \
    'Pad3 KernelSnitch leak child released after post-mm pin exact=1' \
    'Pad3 PIPE KernelSnitch leak child released after post/leak pins exact=1' \
    'Pad3 head guard ready groups=1 sends=8 frees=4 holders=4' \
    'per-group=8/4/4 head=0xe80' \
    'Pad3 reclaim geometry sends=4 truesize=0x9100' \
    'min-sndbuf=0x24401 effective-sndbuf=' \
    'Pad3 mm leak validated pointer=' \
    'order-3 reclaim incomplete close='; do
    grep -aFq "$reclaim_marker" "$pinned_payload" || {
      echo "Pad 3 payload is missing the reclaim marker '$reclaim_marker': " \
           "$pinned_payload" >&2
      exit 4
    }
  done
  for obsolete_ks_gate_marker in \
    'Pad3 slide KernelSnitch quality gate rejected' \
    'clean supervisor retry requested' \
    'Pad3 slide KernelSnitch quality gate accepted'; do
    if grep -aFq "$obsolete_ks_gate_marker" "$pinned_payload"; then
      echo "obsolete cross-stage KernelSnitch route gate survived in payload: " \
           "$obsolete_ks_gate_marker ($pinned_payload)" >&2
      exit 4
    fi
  done
  for guarded_layout_marker in \
    'PSELECT_SHIFT' \
    'PSELECT_SIMPLE_LAYOUT'; do
    if ! grep -aFq "$guarded_layout_marker" "$pinned_payload"; then
      echo "Pad 3 payload cannot reject the layout override without marker " \
           "'$guarded_layout_marker': $pinned_payload" >&2
      exit 4
    fi
  done
  if grep -aFq 'slide boot_id_leaked_nfulnl_logger' "$pinned_payload"; then
    echo "legacy boot-ID slide route survived in Pad 3 payload: $pinned_payload" >&2
    exit 4
  fi
  if grep -aEq 'root umh queued|root umh workqueue|system_unbound_wq|call_usermodehelper_exec_work' \
      "$pinned_payload"; then
    echo "raw workqueue route survived in release payload: $pinned_payload" >&2
    exit 4
  fi
done

echo "==> sync four-artifact hash set into Root My OnePlus Pad 3"
python3 "$ROOT/tools/sync-oneplus-pad3-app-artifacts.py" \
  --payload "$PAYLOAD" \
  --helper "$HELPER" \
  --ksud "$KSUD" \
  --module "$MODULE"
python3 "$ROOT/tools/sync-oneplus-pad3-app-artifacts.py" \
  --payload "$PAYLOAD" \
  --helper "$HELPER" \
  --ksud "$KSUD" \
  --module "$MODULE" \
  --check

echo "==> build Root My OnePlus Pad 3 release APK with the same signer"
APP_APK="$ROOT/app/build/outputs/apk/release/app-release.apk"
rm -f "$APP_APK"
(
  export RMOP_KEYSTORE RMOP_KEY_ALIAS RMOP_STORE_PASSWORD RMOP_KEY_PASSWORD
  cd "$ROOT"
  ./gradlew --no-daemon --no-configuration-cache :app:assembleRelease
)
verify_apk "$APP_APK" "$APP_PACKAGE" 'Root My OnePlus Pad 3'

APP_HASH=$(sha256sum "$APP_APK" | awk '{print $1}')
MANAGER_APK_HASH=$(sha256sum "$MANAGER_APK" | awk '{print $1}')
PAYLOAD_HASH=$(sha256sum "$PAYLOAD" | awk '{print $1}')
HELPER_HASH=$(sha256sum "$HELPER" | awk '{print $1}')
MANIFEST="$WORK/build-manifest.txt"
printf '%s\n' \
  "target=$TARGET" \
  "kernel_release=$KERNEL_RELEASE" \
  "kmi=$KMI" \
  "ksu_pin=$KSU_PIN" \
  "ksu_version=$KSU_VERSION" \
  "manager_certificate_size=$MANAGER_CERT_SIZE_DEC" \
  "manager_certificate_sha256=$MANAGER_CERT_HASH" \
  "payload=$PAYLOAD_HASH $PAYLOAD" \
  "helper=$HELPER_HASH $HELPER" \
  "kernelsu=$MODULE_HASH $MODULE" \
  "ksud=$KSUD_HASH $KSUD" \
  "manager_apk=$MANAGER_APK_HASH $MANAGER_APK" \
  "app_apk=$APP_HASH $APP_APK" > "$MANIFEST"

cat <<DONE

Build complete: one signer-matched OnePlus Pad 3 set
Root My OnePlus Pad 3: $APP_APK
Root My Device KSU:     $MANAGER_APK
ksud:                   $KSUD
kernelsu.ko:            $MODULE
manifest:                $MANIFEST
certificate SHA-256:    $MANAGER_CERT_HASH
certificate DER size:   $MANAGER_CERT_SIZE_DEC

No device was modified by this build.
DONE
