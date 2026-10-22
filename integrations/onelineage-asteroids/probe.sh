#!/system/bin/sh
# Read-only host capability probe for OneLineage on Nothing Phone (3a).
# Does not flash, mount, change SELinux, stop daemons, or run GhostLock.
set -u
prop() { getprop "$1" 2>/dev/null | tr '\r\n' '  '; }
field() { printf '%s=%s\n' "$1" "$2"; }

field PROBE_VERSION 1
for pair in MODEL:ro.product.model DEVICE:ro.product.device PRODUCT:ro.product.name BUILD:ro.build.display.id SDK:ro.build.version.sdk ANDROID:ro.build.version.release PATCH:ro.build.version.security_patch ABI:ro.product.cpu.abi; do
  k=${pair%%:*}; p=${pair#*:}
  field "$k" "$(prop "$p")"
done
field KERNEL "$(uname -r 2>/dev/null)"
field ROOT_UID "$(id -u 2>/dev/null)"
field SELINUX "$(getenforce 2>/dev/null || echo unknown)"
field PAGE_SIZE "$(getconf PAGESIZE 2>/dev/null || echo unknown)"
field CAP_EFF "$(awk '/^CapEff:/ {print $2}' /proc/self/status 2>/dev/null)"

BB=
if command -v busybox >/dev/null 2>&1; then
  BB=$(command -v busybox)
else
  for c in /data/adb/ksu/bin/busybox /data/adb/magisk/busybox /system/xbin/busybox; do
    [ ! -x "$c" ] || { BB=$c; break; }
  done
fi
field BUSYBOX "${BB:-missing}"
for app in unshare nsenter pivot_root losetup mount; do
  key=$(printf '%s' "$app" | tr '[:lower:]' '[:upper:]')
  if [ -n "$BB" ] && "$BB" --list 2>/dev/null | grep -qx "$app"; then
    field "BB_$key" yes
  else
    field "BB_$key" no
  fi
done

# Disposable mount namespace and read-only free-loop lookup.
if [ -n "$BB" ] && "$BB" --list 2>/dev/null | grep -qx unshare; then
  if "$BB" unshare -m /system/bin/sh -c : >/dev/null 2>&1; then
    field MOUNT_NAMESPACE yes
  else
    field MOUNT_NAMESPACE no
  fi
else
  field MOUNT_NAMESPACE unknown
fi
if [ -n "$BB" ] && "$BB" --list 2>/dev/null | grep -qx losetup; then
  if "$BB" losetup -f >/dev/null 2>&1; then
    field FREE_LOOP yes
  else
    field FREE_LOOP no
  fi
else
  field FREE_LOOP unknown
fi

if grep -Eq '^[[:space:]]*nodev[[:space:]]+binder$|^[[:space:]]*binder$' /proc/filesystems 2>/dev/null; then
  field BINDERFS_KERNEL yes
else
  field BINDERFS_KERNEL no
fi
if grep -Eq '^[[:space:]]*ext4$' /proc/filesystems 2>/dev/null; then
  field EXT4_KERNEL yes
else
  field EXT4_KERNEL no
fi
for pair in BINDER:/dev/binder HWBINDER:/dev/hwbinder VNDBINDER:/dev/vndbinder BINDERFS:/dev/binderfs BPF_UID_MAP:/sys/fs/bpf/netd_shared/map_netd_uid_permission_map; do
  k=${pair%%:*}; p=${pair#*:}
  if [ -e "$p" ]; then field "$k" present; else field "$k" missing; fi
done
field APEX_HOST_COUNT "$(find /apex -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')"
field FREE_DATA_KB "$(df -k /data 2>/dev/null | awk 'NR==2{print $4}')"
for pair in ZYGOTE:zygote SURFACEFLINGER:surfaceflinger WIFICOND:wificond NETD:netd ADBD:adbd; do
  k=${pair%%:*}; svc=${pair#*:}
  field "INIT_$k" "$(prop "init.svc.$svc")"
done
field PROBE_WRITE_OPERATIONS none
