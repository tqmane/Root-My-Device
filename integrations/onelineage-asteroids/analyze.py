#!/usr/bin/env python3
"""Read-only Asteroids capability classifier. Never authorizes a takeover."""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

KERNEL = "6.1.157-android14-11-g82d681c9b06b-ab14634535"
PROFILES = {
    "B4.1-260618-1048": ("36", "2026-06-01"),
    "B4.1-260810-1153": ("36", "2026-08-01"),
    "C5.0-260915-2123": ("37", "2026-09-01"),
}

def parse_probe(text: str) -> dict[str, str]:
    result = {}
    for line in text.splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        if key.replace("_", "").isalnum() and key.upper() == key:
            result[key] = value.strip()
    return result

def analyze(p: dict[str, str]) -> tuple[list[tuple[str, str]], bool]:
    checks: list[tuple[str, str]] = []
    blocked = False
    def report(level: str, message: str) -> None:
        nonlocal blocked
        checks.append((level, message))
        blocked |= level == "FAIL"

    if p.get("MODEL", "").upper() != "A059" or p.get("DEVICE", "").lower() != "asteroids":
        report("FAIL", "Expected A059 / Asteroids")
    else:
        report("PASS", "Correct device identity")
    build = p.get("BUILD", "")
    matches = [name for name in PROFILES if build == name or build.endswith("-" + name) or build.endswith("-" + name + "-JPN")]
    if len(matches) != 1:
        report("FAIL", "Unknown exact Root My Device build")
    else:
        sdk, patch = PROFILES[matches[0]]
        if p.get("SDK") != sdk or p.get("PATCH") != patch:
            report("FAIL", "SDK or security patch does not match the exact profile")
        else:
            report("PASS", "Exact supported Root My Device profile " + matches[0])
    if p.get("SDK") != "36":
        report("FAIL", "Android 17 host is unsupported by this Android 16 guest experiment")
    if p.get("KERNEL") != KERNEL:
        report("FAIL", "Kernel identity mismatch")
    if p.get("ABI") != "arm64-v8a" or p.get("PAGE_SIZE") != "4096":
        report("FAIL", "Expected arm64-v8a with 4 KiB page size")
    if p.get("ROOT_UID") != "0":
        report("FAIL", "KernelSU root not active or not granted to this shell")
    try:
        caps = int(p.get("CAP_EFF", ""), 16)
    except ValueError:
        caps = 0
    if not caps & (1 << 21):
        report("FAIL", "CAP_SYS_ADMIN missing")
    if p.get("BUSYBOX", "missing") == "missing":
        report("FAIL", "BusyBox not found")
    for app in ("UNSHARE", "NSENTER", "PIVOT_ROOT", "LOSETUP", "MOUNT"):
        if p.get("BB_" + app) != "yes":
            report("FAIL", "BusyBox " + app.lower() + " missing")
    if p.get("MOUNT_NAMESPACE") != "yes":
        report("FAIL", "Private mount namespace unavailable")
    if p.get("FREE_LOOP") != "yes":
        report("FAIL", "No free loop device; do not create device nodes blindly")
    if p.get("EXT4_KERNEL") != "yes":
        report("FAIL", "ext4 support unavailable")
    if p.get("BINDER") != "present" and p.get("BINDERFS") != "present":
        report("FAIL", "Binder device missing")
    try:
        free_kb = int(p.get("FREE_DATA_KB", "0"))
    except ValueError:
        free_kb = 0
    if free_kb < 6 * 1024 * 1024:
        report("FAIL", "Less than 6 GiB free on /data")
    if p.get("SELINUX") == "Enforcing":
        report("WARN", "SELinux enforcing: Nothing-specific policy audit required")
    elif p.get("SELINUX") == "Permissive":
        report("WARN", "SELinux permissive: inspect security exposure")
    else:
        report("WARN", "SELinux state unknown")
    for svc in ("ZYGOTE", "SURFACEFLINGER", "NETD"):
        if p.get("INIT_" + svc) != "running":
            report("WARN", "Host service " + svc.lower() + " not running / different name")
    report("WARN", "Samsung framework/APEX, IMS, Binder/HAL and return-to-stock logic are NOT ported")
    report("WARN", "Probe does not authorize or trigger userspace takeover")
    return checks, blocked

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    p = parse_probe(args.report.read_text(encoding="utf-8", errors="replace"))
    checks, blocked = analyze(p)
    for level, message in checks:
        print(f"[{level:4s}] {message}")
    print("\nOneLineage takeover supported: NO (port not completed or verified)")
    print("Basic capabilities: " + ("BLOCKED" if blocked else "READY FOR FURTHER RESEARCH"))
    return 2 if blocked else 0

if __name__ == "__main__":
    sys.exit(main())
