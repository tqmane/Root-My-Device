#!/usr/bin/env bash
# Collect OnePlus Pad 3 KernelSU late-load state. Collection is the default and
# is read-only. --run explicitly stages local binaries and restarts framework.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
KERNEL_RELEASE='6.6.118-android15-8-g2e6b9c3812c5-ab15114928-4k'
TARGET_SLUG="oneplus-pad3_ex_$KERNEL_RELEASE"
HELPER="$ROOT/build/$TARGET_SLUG/cve-2026-43499-root"
KSUD="$ROOT/build/oneplus-pad3-fixed/ksud-oneplus-pad3"
MANAGER_APK="$ROOT/build/oneplus-pad3-fixed/manager-dist/RootMyDeviceKSU_32525_OnePlusPad3.apk"
MODE='collect'
ASSUME_YES=0
SERIAL=''

usage() {
  cat <<'USAGE'
Usage:
  diagnostics/oneplus-pad3/late-load-oneplus-pad3.sh [--serial SERIAL]
  diagnostics/oneplus-pad3/late-load-oneplus-pad3.sh --run --yes [--serial SERIAL]

Default: read-only collection of target, KernelSU, mount namespace, module,
zygote/system_server, Vector/NeoZygisk, and boot-ID completion state.

--run: push the locally built helper/ksud and execute the explicit module
late-load path. This modifies /data/local/tmp and can restart zygote/framework.
It is valid only after the exploit has established the temporary-root daemon
for the current boot. --yes is required to acknowledge the transition.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --run) MODE='run' ;;
    --collect) MODE='collect' ;;
    --yes) ASSUME_YES=1 ;;
    --serial)
      [ "$#" -ge 2 ] || { echo "--serial requires a value" >&2; exit 2; }
      SERIAL=$2
      shift
      ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

command -v adb >/dev/null 2>&1 || { echo "adb not found" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "python3 not found" >&2; exit 2; }
adb_args=()
verify_args=()
if [ -n "$SERIAL" ]; then
  adb_args=(-s "$SERIAL")
  verify_args=(--serial "$SERIAL")
fi
adb_cmd() {
  adb "${adb_args[@]}" "$@"
}

python3 "$ROOT/tools/verify-target.py" "${verify_args[@]}"

collect_script=$(cat <<'DEVICE_SCRIPT'
echo '=== TARGET ==='
echo "model=$(getprop ro.product.model)"
echo "device=$(getprop ro.product.device)"
echo "product=$(getprop ro.product.name)"
echo "build=$(getprop ro.build.display.id)"
echo "fingerprint=$(getprop ro.build.fingerprint)"
echo "kernel=$(uname -r)"
echo "page_size=$(getconf PAGESIZE)"
echo "slot=$(getprop ro.boot.slot_suffix)"
echo "verified_boot=$(getprop ro.boot.verifiedbootstate)"

echo '=== COMPLETION CONTRACT ==='
boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)
marker_path=/data/local/tmp/.ksu-late-load-modules-ok
marker_version=$(sed -n 's/^version=//p' "$marker_path" 2>/dev/null || true)
marker_boot_id=$(sed -n 's/^boot_id=//p' "$marker_path" 2>/dev/null || true)
marker_run_id=$(sed -n 's/^run_id=//p' "$marker_path" 2>/dev/null || true)
marker_ksud_sha=$(sed -n 's/^ksud_sha256=//p' "$marker_path" 2>/dev/null || true)
marker_stat=$(stat -c '%u:%g:%a:%h' "$marker_path" 2>/dev/null || true)
echo "boot_id=$boot_id"
echo "marker_version=$marker_version"
echo "marker_boot_id=$marker_boot_id"
echo "marker_run_id=$marker_run_id"
echo "marker_ksud_sha256=$marker_ksud_sha"
echo "marker_uid_gid_mode_nlink=$marker_stat"
case "$marker_run_id" in ''|*[!0-9a-f]*) run_id_valid=0 ;; *) run_id_valid=1 ;; esac
case "$marker_ksud_sha" in ''|*[!0-9a-f]*) hash_valid=0 ;; *) hash_valid=1 ;; esac
if [ "$marker_version" = 1 ] && [ -n "$boot_id" ] && \
   [ "$marker_boot_id" = "$boot_id" ] && \
   [ "$run_id_valid" = 1 ] && [ "${#marker_run_id}" -eq 32 ] && \
   [ "$hash_valid" = 1 ] && [ "${#marker_ksud_sha}" -eq 64 ] && \
   [ "$marker_stat" = '0:0:644:1' ]; then
  echo 'completion=nonce-bound-current-boot-receipt'
elif [ -n "$marker_version" ]; then
  echo 'completion=invalid-stale-or-untrusted-receipt'
else
  echo 'completion=missing'
fi

echo '=== RANDOM UUID SLIDE ORACLE ==='
# Read the UUID sysctl twice but never print either value: a pristine NULL
# data slot regenerates, while a stable pair is the fail-stop signature used
# by the Pad 3 slide preflight.  This is observation only.
uuid_xtrace=0
case "$-" in
  *x*) uuid_xtrace=1; set +x ;;
esac
uuid_first=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || true)
uuid_second=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || true)
uuid_chars=$uuid_first$uuid_second
if [ "${#uuid_first}" -eq 36 ] && [ "${#uuid_second}" -eq 36 ]; then
  case "$uuid_chars" in
    *[!0-9a-fA-F-]*) uuid_result='uuid_reads=incomplete stable=unknown' ;;
    *)
      if [ "$uuid_first" = "$uuid_second" ]; then
        uuid_result='uuid_reads=complete stable=1'
      else
        uuid_result='uuid_reads=complete stable=0'
      fi
      ;;
  esac
else
  uuid_result='uuid_reads=incomplete stable=unknown'
fi
unset uuid_first uuid_second uuid_chars
if [ "$uuid_xtrace" -eq 1 ]; then set -x; fi
echo "$uuid_result"
unset uuid_result uuid_xtrace

echo '=== KERNELSU ==='
if [ -d /sys/module/kernelsu ]; then echo 'module=sysfs-present'; else echo 'module=sysfs-missing'; fi
grep '^kernelsu ' /proc/modules 2>/dev/null || true
for candidate in /data/adb/ksud /data/local/tmp/ksud; do
  if [ -x "$candidate" ]; then
    echo "ksud_path=$candidate"
    "$candidate" --version 2>&1 || "$candidate" -V 2>&1 || true
  fi
done

echo '=== MANAGER ==='
pm path org.witaqua.pwn.kernelsu 2>/dev/null || true
dumpsys package org.witaqua.pwn.kernelsu 2>/dev/null |
  grep -E 'versionName=|versionCode=|signatures=|SigningInfo|flags=' |
  head -30 || true

echo '=== MOUNT NAMESPACES ==='
printf 'pid1='; readlink /proc/1/ns/mnt 2>/dev/null || true
echo
printf 'self='; readlink /proc/self/ns/mnt 2>/dev/null || true
for pid in $(pidof ksud 2>/dev/null); do
  printf 'ksud[%s]=' "$pid"
  readlink "/proc/$pid/ns/mnt" 2>/dev/null || true
done

echo '=== FRAMEWORK ==='
echo "zygote_state=$(getprop init.svc.zygote)"
echo "zygote64_state=$(getprop init.svc.zygote64)"
printf 'zygote_pids='; pidof zygote64 zygote 2>/dev/null || true
printf 'system_server_pid='; pidof system_server 2>/dev/null || true

echo '=== MODULES ==='
for directory in /data/adb/modules/*; do
  [ -d "$directory" ] || continue
  echo "--- $directory ---"
  sed -n '1,12p' "$directory/module.prop" 2>/dev/null || true
  for stage in late-load.sh post-fs-data.sh post-mount.sh service.sh; do
    if [ -f "$directory/$stage" ]; then
      echo "$stage=present"
    fi
  done
done

echo '=== NEOZYGISK / VECTOR / LSPOSED ==='
ps -A -o PID,PPID,USER,CONTEXT,ARGS 2>/dev/null |
  grep -Ei 'zygisk|zygote|lspd|lsposed|vector' || true
for socket in /data/adb/lspd/.cli_sock /data/adb/modules/zygisk_vector/.cli_sock; do
  if [ -S "$socket" ]; then echo "socket=$socket ready"; else echo "socket=$socket missing"; fi
done
if [ -f /data/adb/modules/zygisk_vector/service.sh ]; then
  vector_dir=/data/adb/modules/zygisk_vector
  if [ -f "$vector_dir/service.sh" ] && [ ! -x "$vector_dir/service.sh" ]; then
    echo 'vector_service_script=regular-nonexecutable-ok'
  else
    echo 'vector_service_script=unexpected-type-or-mode'
  fi
  if [ -f "$vector_dir/action.sh" ] && [ ! -x "$vector_dir/action.sh" ]; then
    echo 'vector_action_script=regular-nonexecutable-ok'
  else
    echo 'vector_action_script=unexpected-type-or-mode'
  fi
  if [ -f "$vector_dir/daemon" ] && [ -x "$vector_dir/daemon" ]; then
    echo 'vector_daemon=regular-executable-ok'
  else
    echo 'vector_daemon=unexpected-type-or-mode'
  fi
  if grep -q -- '--propagation' /data/adb/modules/zygisk_vector/service.sh; then
    echo 'vector_toybox_adapter=required'
  else
    echo 'vector_toybox_adapter=not-detected'
  fi
fi

echo '=== RECENT LOGS ==='
logcat -d -t 800 2>/dev/null |
  grep -Ei 'KernelSU|ksud|late-load|oneplus.pad|zygisk|neoz|lsposed|lspd|vector|system_server' |
  tail -250 || true
DEVICE_SCRIPT
)

collect() {
  if adb_cmd shell 'command -v su >/dev/null 2>&1' >/dev/null 2>&1; then
    printf '%s\n' "$collect_script" | adb_cmd shell su -c sh
  else
    echo "[!] su is unavailable; collecting the shell-readable subset" >&2
    printf '%s\n' "$collect_script" | adb_cmd shell sh
  fi

  if [ -s "$MANAGER_APK" ] && command -v apksigner >/dev/null 2>&1; then
    echo '=== EXPECTED LOCAL MANAGER CERTIFICATE ==='
    apksigner verify --print-certs "$MANAGER_APK" |
      sed -n 's/^Signer #1 certificate SHA-256 digest: /sha256=/p'
  fi
}

if [ "$MODE" = 'collect' ]; then
  collect
  exit 0
fi

if [ "$ASSUME_YES" -ne 1 ]; then
  echo "--run writes staging files and may restart zygote/framework; pass --yes" >&2
  exit 2
fi
for artifact in "$HELPER" "$KSUD"; do
  [ -s "$artifact" ] || {
    echo "missing $artifact -- run tools/build-oneplus-pad3.sh --release first" >&2
    exit 2
  }
done

echo "==> staging exact helper and ksud; framework may restart"
adb_cmd push "$HELPER" /data/local/tmp/cve-2026-43499-root >/dev/null
adb_cmd push "$KSUD" /data/local/tmp/ksud >/dev/null
adb_cmd shell 'chmod 755 /data/local/tmp/cve-2026-43499-root /data/local/tmp/ksud'

run_id=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
echo "requested_run_id=$run_id"
set +e
adb_cmd shell \
  "/data/local/tmp/cve-2026-43499-root --late-load android15-6.6 org.witaqua.pwn.kernelsu modules run-id=$run_id"
late_load_rc=$?
set -e
echo "late_load_rc=$late_load_rc"
adb_cmd wait-for-device
sleep 3
collect
exit "$late_load_rc"
