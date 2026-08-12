#!/bin/sh
# Manual Asteroids late-load module test. Run only after the standalone exploit
# has already established the temporary-root daemon for this boot.
set -eu

TARGET_DIR="build/asteroids_jp_6.1.157-android14-11-g82d681c9b06b-ab14634535"
HELPER="$TARGET_DIR/cve-2026-43499-root"
KSUD="build/asteroids-fixed/ksud-asteroids"

for file in "$HELPER" "$KSUD"; do
  [ -f "$file" ] || { echo "missing $file -- run tools/build-asteroids-fixed.sh first" >&2; exit 1; }
done

SERIAL=${ADB_SERIAL:-}
if [ -z "$SERIAL" ]; then
  SERIAL=$(adb devices -l | awk '/ model:A059 / { print $1 }')
fi
[ -n "$SERIAL" ] && [ "$(printf '%s\n' "$SERIAL" | wc -l)" -eq 1 ] || {
  echo "set ADB_SERIAL to the Nothing A059 serial" >&2
  exit 1
}
adb_target() { adb -s "$SERIAL" "$@"; }

adb_target get-state >/dev/null 2>&1 || { echo "A059 is not available on adb" >&2; exit 1; }
adb_target push "$KSUD" /data/local/tmp/ksud.rmn-tmp.diag >/dev/null
adb_target shell 'chmod 755 /data/local/tmp/ksud.rmn-tmp.diag && mv -f /data/local/tmp/ksud.rmn-tmp.diag /data/local/tmp/ksud'

echo "Starting patched KernelSU + module compatibility. Framework WILL restart."
set +e
if adb_target shell 'su -M -c /system/bin/id' 2>/dev/null | grep -q 'uid=0'; then
  adb_target shell 'cp /data/local/tmp/ksud /data/local/tmp/.ksud-stage && chmod 755 /data/local/tmp/.ksud-stage && su -M -c "/data/local/tmp/ksud late-load --kmi android14-6.1 --package-name org.witaqua.pwn.kernelsu --modules"'
else
  adb_target push "$HELPER" /data/local/tmp/cve-2026-43499-root.rmn-tmp.diag >/dev/null
  adb_target shell 'chmod 755 /data/local/tmp/cve-2026-43499-root.rmn-tmp.diag && mv -f /data/local/tmp/cve-2026-43499-root.rmn-tmp.diag /data/local/tmp/cve-2026-43499-root'
  adb_target shell '/data/local/tmp/cve-2026-43499-root --late-load android14-6.1 org.witaqua.pwn.kernelsu modules'
fi
rc=$?
set -e

echo "helper rc=$rc"
sleep 3
adb_target wait-for-device
adb_target shell '
echo === COMPLETION ===
echo marker=$(cat /data/local/tmp/.ksu-late-load-modules-ok 2>/dev/null)
echo boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
cat /data/local/tmp/root-my-nothing-modules.log 2>/dev/null || true
echo === FRAMEWORK ===
echo zygote=$(getprop init.svc.zygote)
pidof zygote64 zygote system_server 2>/dev/null || true
echo === MODULES ===
for d in /data/adb/modules/*; do
  [ -d "$d" ] || continue
  echo ==== "$d" ====
  cat "$d/module.prop" 2>/dev/null | head -8
  ls -l "$d"/late-load.sh "$d"/post-fs-data.sh "$d"/post-mount.sh "$d"/service.sh 2>/dev/null || true
done
echo === PROCESSES ===
ps -A -o PID,PPID,USER,CONTEXT,ARGS | grep -Ei "zygisk|zygote|lspd|lsposed|vector" || true
echo === VECTOR_CLI ===
su -M -c "/system/bin/sh /data/adb/modules/zygisk_vector/cli --json status" 2>/dev/null || true
'

echo "=== LOGCAT ==="
adb_target logcat -d | grep -Ei 'KernelSU|ksud|late-load|Asteroids late-load|zygisk|neoz|lsposed|lspd|vector' | tail -250 || true
exit "$rc"
