#!/usr/bin/env python3
"""Read-only exact-build guard for the supported OnePlus Pad 3 firmware."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass

EXPECTED = {
    "model": "OPD2415",
    "device": "OP6190L1",
    "product": "OPD2415IN",
    "hardware": "qcom",
    "fingerprint": (
        "OnePlus/OPD2415IN/OP6190L1:16/AP3A.240617.008/"
        "V.R4T3.17bf73d_cf42a1_c9913b:user/release-keys"
    ),
    "display": "OPD2415_16.0.9.400(EX01)",
    "incremental": "V.R4T3.17bf73d_cf42a1_c9913b",
    "security_patch": "2026-07-01",
    "android": "16",
    "sdk": "36",
    "kernel_release": "6.6.118-android15-8-g2e6b9c3812c5-ab15114928-4k",
    "page_size": "4096",
    "abi": "arm64-v8a",
}

POLICY_PATH = "/system/etc/selinux/plat_sepolicy.cil"
POLICY_EXPECTED = {
    "plat_sepolicy_metadata": "0|0|644|2342112|regular file",
    "plat_sepolicy_sha256": "8c2a6cb31d87d70efb3f98760704d8d3f17da32ce75704db27185f314044ac22",
    "plat_sepolicy_fork_allow": "present",
    "plat_sepolicy_kernel_domain": "present",
}
POLICY_FORK_ALLOW = (
    b"(allow domain self (process (fork sigchld sigkill sigstop signull signal "
    b"getsched setsched getsession getpgid getcap setcap getattr setrlimit)))"
)

PROPERTY_MAP = {
    "model": "ro.product.model",
    "device": "ro.product.device",
    "product": "ro.product.name",
    "hardware": "ro.hardware",
    "fingerprint": "ro.build.fingerprint",
    "display": "ro.build.display.id",
    "incremental": "ro.build.version.incremental",
    "security_patch": "ro.build.version.security_patch",
    "android": "ro.build.version.release",
    "sdk": "ro.build.version.sdk",
    "abi": "ro.product.cpu.abi",
}

OBSERVED_BOOT_PROPERTIES = {
    "slot_suffix": "ro.boot.slot_suffix",
    "flash_locked": "ro.boot.flash.locked",
    "vbmeta_device_state": "ro.boot.vbmeta.device_state",
    "verified_boot_state": "ro.boot.verifiedbootstate",
    "verity_mode": "ro.boot.veritymode",
    "avb_version": "ro.boot.avb_version",
    "dynamic_partitions": "ro.boot.dynamic_partitions",
    "virtual_ab": "ro.virtual_ab.enabled",
    "crypto_state": "ro.crypto.state",
}


class VerificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Device:
    serial: str
    state: str
    description: str


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )
    except subprocess.TimeoutExpired as exc:
        raise VerificationError(f"command timed out: {command[0]}") from exc
    except OSError as exc:
        raise VerificationError(f"cannot execute {command[0]}: {exc}") from exc


def run_bytes(command: list[str]) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )
    except subprocess.TimeoutExpired as exc:
        raise VerificationError(f"command timed out: {command[0]}") from exc
    except OSError as exc:
        raise VerificationError(f"cannot execute {command[0]}: {exc}") from exc


def select_device(adb: str, requested_serial: str | None) -> Device:
    result = run([adb, "devices", "-l"])
    if result.returncode != 0:
        raise VerificationError(result.stderr.strip() or "adb devices failed")

    devices: list[Device] = []
    for line in result.stdout.splitlines()[1:]:
        fields = line.strip().split()
        if len(fields) < 2:
            continue
        devices.append(Device(fields[0], fields[1], " ".join(fields[2:])))

    if requested_serial:
        matches = [device for device in devices if device.serial == requested_serial]
        if not matches:
            raise VerificationError(f"adb device not found: {requested_serial}")
        selected = matches[0]
    else:
        usable = [device for device in devices if device.state == "device"]
        if not usable:
            states = ", ".join(f"{d.serial}:{d.state}" for d in devices) or "none"
            raise VerificationError(f"no authorized adb device (seen: {states})")
        if len(usable) != 1:
            serials = ", ".join(device.serial for device in usable)
            raise VerificationError(f"multiple adb devices ({serials}); pass --serial")
        selected = usable[0]

    if selected.state != "device":
        raise VerificationError(
            f"adb device {selected.serial} is {selected.state}, expected device"
        )
    return selected


def collect(adb: str, device: Device) -> dict[str, str]:
    lines = [
        f'printf "{key}=%s\\n" "$(getprop {prop})"'
        for key, prop in {**PROPERTY_MAP, **OBSERVED_BOOT_PROPERTIES}.items()
    ]
    lines.extend(
        [
            'printf "kernel_release=%s\\n" "$(uname -r)"',
            'printf "page_size=%s\\n" "$(getconf PAGESIZE)"',
            'printf "selinux=%s\\n" "$(getenforce 2>/dev/null)"',
            'if command -v su >/dev/null 2>&1; then printf "su_binary=present\\n"; '
            'else printf "su_binary=absent\\n"; fi',
        ]
    )
    # adb concatenates arguments into a remote shell command; passing separate
    # `sh`, `-c`, command argv entries loses the command's quoting and leaves
    # only the first printf attached to -c.  The joined string is already a
    # POSIX-shell program, so hand it to adb as the single remote command.
    result = run([adb, "-s", device.serial, "shell", "; ".join(lines)])
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise VerificationError(f"failed to query {device.serial}: {detail}")

    values: dict[str, str] = {}
    for raw_line in result.stdout.replace("\r", "").splitlines():
        if "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        values[key] = value
    missing = [key for key in EXPECTED if key not in values]
    if missing:
        raise VerificationError("device response omitted: " + ", ".join(missing))
    return values


def collect_policy(adb: str, device: Device) -> dict[str, str]:
    stat_result = run(
        [
            adb,
            "-s",
            device.serial,
            "shell",
            f"stat -c '%u|%g|%a|%s|%F' {POLICY_PATH}",
        ]
    )
    if stat_result.returncode != 0:
        raise VerificationError(
            stat_result.stderr.strip() or "plat_sepolicy.cil stat failed"
        )
    metadata = stat_result.stdout.replace("\r", "").strip()
    policy_result = run_bytes(
        [adb, "-s", device.serial, "exec-out", "cat", POLICY_PATH]
    )
    if policy_result.returncode != 0:
        detail = policy_result.stderr.decode(errors="replace").strip()
        raise VerificationError(detail or "plat_sepolicy.cil read failed")
    policy = policy_result.stdout
    kernel_domain = re.search(
        rb"\(typeattributeset\s+domain\s+\([^\)]*\bkernel\b[^\)]*\)\)",
        policy,
    ) is not None
    return {
        "plat_sepolicy_metadata": metadata,
        "plat_sepolicy_sha256": hashlib.sha256(policy).hexdigest(),
        "plat_sepolicy_fork_allow": (
            "present" if POLICY_FORK_ALLOW in policy else "missing"
        ),
        "plat_sepolicy_kernel_domain": "present" if kernel_domain else "missing",
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify the connected device is the exact supported Pad 3 build"
    )
    parser.add_argument("--serial", help="adb serial; required when several devices are connected")
    parser.add_argument("--adb", default="adb", help="adb executable")
    parser.add_argument("--json", action="store_true", help="emit a machine-readable report")
    parser.add_argument(
        "--require-locked",
        action="store_true",
        help="also fail unless the bootloader reports locked/green",
    )
    args = parser.parse_args()

    adb = shutil.which(args.adb) if "/" not in args.adb else args.adb
    if not adb:
        print(f"error: adb not found: {args.adb}", file=sys.stderr)
        return 2

    try:
        device = select_device(adb, args.serial)
        actual = collect(adb, device)
        actual.update(collect_policy(adb, device))
    except VerificationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    mismatches = {
        key: {"expected": expected, "actual": actual.get(key, "")}
        for key, expected in EXPECTED.items()
        if actual.get(key) != expected
    }
    mismatches.update(
        {
            key: {"expected": expected, "actual": actual.get(key, "")}
            for key, expected in POLICY_EXPECTED.items()
            if actual.get(key) != expected
        }
    )
    if args.require_locked:
        security_expected = {
            "flash_locked": "1",
            "vbmeta_device_state": "locked",
            "verified_boot_state": "green",
        }
        mismatches.update(
            {
                key: {"expected": expected, "actual": actual.get(key, "")}
                for key, expected in security_expected.items()
                if actual.get(key) != expected
            }
        )

    report = {
        "compatible": not mismatches,
        "target": "oneplus-pad3",
        "target_id": "oneplus-pad3-opd2415-16.0.9.400-ex01",
        "serial": device.serial,
        "adb_state": device.state,
        "transport": device.description,
        "expected": {**EXPECTED, **POLICY_EXPECTED},
        "actual": actual,
        "mismatches": mismatches,
    }

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        status = "MATCH" if not mismatches else "MISMATCH"
        print(f"target    {status}: oneplus-pad3-opd2415-16.0.9.400-ex01")
        print(f"serial    {device.serial}")
        for key in EXPECTED:
            print(f"{key:14} {actual.get(key, '<missing>')}")
        print(
            "boot_state     "
            f"locked={actual.get('flash_locked')} "
            f"vbmeta={actual.get('vbmeta_device_state')} "
            f"verified={actual.get('verified_boot_state')} "
            f"verity={actual.get('verity_mode')}"
        )
        print(
            "runtime        "
            f"slot={actual.get('slot_suffix')} selinux={actual.get('selinux')} "
            f"su={actual.get('su_binary')}"
        )
        print(
            "policy         "
            f"sha256={actual.get('plat_sepolicy_sha256')} "
            f"metadata={actual.get('plat_sepolicy_metadata')} "
            f"fork={actual.get('plat_sepolicy_fork_allow')} "
            f"kernel_domain={actual.get('plat_sepolicy_kernel_domain')}"
        )
        for key, mismatch in mismatches.items():
            print(
                f"mismatch  {key}: {mismatch['actual']!r} != {mismatch['expected']!r}",
                file=sys.stderr,
            )
    return 0 if not mismatches else 1


if __name__ == "__main__":
    raise SystemExit(main())
