#!/usr/bin/env python3
"""Extract and fingerprint the exact OnePlus Pad 3 Android boot image.

Android boot image header v3/v4 uses a fixed 4096-byte payload alignment.  The
tool deliberately validates the exact Pad 3 kernel release by default so an
OTA image cannot silently replace the profiling input.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import struct
import sys
from pathlib import Path

BOOT_MAGIC = b"ANDROID!"
BOOT_ALIGNMENT = 4096
EXPECTED_HEADER_VERSION = 4
EXPECTED_KERNEL_RELEASE = (
    "6.6.118-android15-8-g2e6b9c3812c5-ab15114928-4k"
)
EXPECTED_BOOT_SHA256 = "0e584a801f2214758758221feb47dd3e06736d0a348709780bd58aea78fc420f"
EXPECTED_KERNEL_SHA256 = "d4d2cbf9cf97e522b2e4a4ba8cee6b1ef205eaa5b04d632a25b0e21c8c817bf5"
EXPECTED_IKCONFIG_SHA256 = "032ff35b6657c91047c93090a1884993ca622d0720fc2bb772a7ef0558c3fb7e"
IKCONFIG_START = b"IKCFG_ST"
IKCONFIG_END = b"IKCFG_ED"


def align(value: int, alignment: int = BOOT_ALIGNMENT) -> int:
    return (value + alignment - 1) // alignment * alignment


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_bytes(destination: Path, data: bytes, *, force: bool) -> None:
    if destination.exists() and not force:
        raise FileExistsError(f"refusing to overwrite {destination}; pass --force")
    temporary = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
    try:
        with temporary.open("wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def extract_ikconfig(kernel: bytes) -> bytes | None:
    start = kernel.find(IKCONFIG_START)
    if start < 0:
        return None
    start += len(IKCONFIG_START)
    end = kernel.find(IKCONFIG_END, start)
    if end < 0:
        raise ValueError("found IKCFG_ST without IKCFG_ED")
    try:
        config = gzip.decompress(kernel[start:end])
    except (gzip.BadGzipFile, EOFError, OSError) as exc:
        raise ValueError(f"embedded IKCONFIG gzip stream is invalid: {exc}") from exc
    if not config.startswith(b"CONFIG_") and b"\nCONFIG_" not in config:
        raise ValueError("embedded IKCONFIG did not decode to a kernel config")
    return config


def parse_config(config: bytes) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for raw_line in config.decode("utf-8", errors="replace").splitlines():
        if raw_line.startswith("CONFIG_") and "=" in raw_line:
            key, value = raw_line.split("=", 1)
            parsed[key] = value
    return parsed


def config_profile(config: dict[str, str]) -> dict[str, object]:
    page_size = None
    for option, value in (
        ("CONFIG_ARM64_4K_PAGES", 4096),
        ("CONFIG_ARM64_16K_PAGES", 16384),
        ("CONFIG_ARM64_64K_PAGES", 65536),
    ):
        if config.get(option) == "y":
            page_size = value
            break

    def enabled(name: str) -> bool:
        return config.get(name) == "y"

    def integer(name: str) -> int | None:
        raw = config.get(name)
        if raw is None:
            return None
        try:
            return int(raw, 0)
        except ValueError:
            return None

    return {
        "page_size": page_size,
        "va_bits": integer("CONFIG_ARM64_VA_BITS"),
        "pa_bits": integer("CONFIG_ARM64_PA_BITS"),
        "modules": enabled("CONFIG_MODULES"),
        "module_unload": enabled("CONFIG_MODULE_UNLOAD"),
        "module_sig": enabled("CONFIG_MODULE_SIG"),
        "modversions": enabled("CONFIG_MODVERSIONS"),
        "ikconfig": enabled("CONFIG_IKCONFIG"),
        "ikconfig_proc": enabled("CONFIG_IKCONFIG_PROC"),
        "btf": enabled("CONFIG_DEBUG_INFO_BTF"),
        "btf_modules": enabled("CONFIG_DEBUG_INFO_BTF_MODULES"),
        "kallsyms": enabled("CONFIG_KALLSYMS"),
        "kallsyms_all": enabled("CONFIG_KALLSYMS_ALL"),
        "kallsyms_base_relative": enabled("CONFIG_KALLSYMS_BASE_RELATIVE"),
        "ashmem": enabled("CONFIG_ASHMEM"),
        "configfs": enabled("CONFIG_CONFIGFS_FS"),
        "randomize_base": enabled("CONFIG_RANDOMIZE_BASE"),
        "cfi_clang": enabled("CONFIG_CFI_CLANG"),
        "shadow_call_stack": enabled("CONFIG_SHADOW_CALL_STACK"),
        "pointer_auth": enabled("CONFIG_ARM64_PTR_AUTH"),
    }


def find_string(data: bytes, pattern: bytes) -> str | None:
    match = re.search(pattern, data)
    if match is None:
        return None
    return match.group(1).decode("utf-8", errors="replace").strip()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract exact OnePlus Pad 3 boot v4 kernel, ramdisk, and IKCONFIG"
    )
    parser.add_argument("boot_image", type=Path)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("generated/oneplus-pad-3"),
    )
    parser.add_argument(
        "--expect-kernel-release",
        default=EXPECTED_KERNEL_RELEASE,
        help="exact release required in the extracted kernel",
    )
    parser.add_argument(
        "--expect-boot-sha256",
        default=EXPECTED_BOOT_SHA256,
        help="full boot.img SHA-256 pin (defaults to the exact EX01 image)",
    )
    parser.add_argument(
        "--expect-kernel-sha256",
        default=EXPECTED_KERNEL_SHA256,
        help="extracted kernel SHA-256 pin",
    )
    parser.add_argument("--allow-other-header", action="store_true")
    parser.add_argument("--allow-missing-ikconfig", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    boot_image = args.boot_image.expanduser().resolve()
    if not boot_image.is_file():
        parser.error(f"boot image not found: {boot_image}")

    boot_size = boot_image.stat().st_size
    if boot_size < BOOT_ALIGNMENT:
        raise SystemExit("boot image is smaller than one header page")

    boot_hash = sha256_file(boot_image)
    if args.expect_boot_sha256 and boot_hash.lower() != args.expect_boot_sha256.lower():
        raise SystemExit(
            f"boot image SHA-256 mismatch: {boot_hash} != {args.expect_boot_sha256.lower()}"
        )

    with boot_image.open("rb") as source:
        header = source.read(BOOT_ALIGNMENT)
        if header[:8] != BOOT_MAGIC:
            raise SystemExit("not an Android boot image: missing ANDROID! magic")
        kernel_size, ramdisk_size, os_version, header_size = struct.unpack_from(
            "<4I", header, 8
        )
        header_version = struct.unpack_from("<I", header, 40)[0]
        if header_version != EXPECTED_HEADER_VERSION and not args.allow_other_header:
            raise SystemExit(
                f"boot header version {header_version}, expected {EXPECTED_HEADER_VERSION}"
            )
        if header_size <= 0 or header_size > BOOT_ALIGNMENT:
            raise SystemExit(f"invalid boot header size: {header_size}")

        kernel_offset = align(header_size)
        ramdisk_offset = align(kernel_offset + kernel_size)
        signature_size = (
            struct.unpack_from("<I", header, 1580)[0]
            if header_version >= 4 and header_size >= 1584
            else 0
        )
        signature_offset = align(ramdisk_offset + ramdisk_size)
        required_size = signature_offset + signature_size
        if kernel_size <= 0:
            raise SystemExit("boot header reports an empty kernel")
        if required_size > boot_size:
            raise SystemExit(
                f"boot payloads exceed file size: need {required_size}, have {boot_size}"
            )

        source.seek(kernel_offset)
        kernel = source.read(kernel_size)
        if len(kernel) != kernel_size:
            raise SystemExit("boot image ended while reading the kernel")
        source.seek(ramdisk_offset)
        ramdisk = source.read(ramdisk_size)
        if len(ramdisk) != ramdisk_size:
            raise SystemExit("boot image ended while reading the ramdisk")

    kernel_hash = sha256_bytes(kernel)
    if kernel_hash.lower() != args.expect_kernel_sha256.lower():
        raise SystemExit(
            f"kernel SHA-256 mismatch: {kernel_hash} != {args.expect_kernel_sha256.lower()}"
        )
    linux_version = find_string(
        kernel,
        rb"Linux version\s+([^\x00\r\n]{1,256})",
    )
    kernel_release = None
    if linux_version:
        kernel_release = linux_version.split(maxsplit=1)[0]
    if kernel_release != args.expect_kernel_release:
        raise SystemExit(
            "kernel release mismatch: "
            f"{kernel_release or '<not found>'} != {args.expect_kernel_release}"
        )

    compiler = find_string(
        kernel,
        rb"((?:Android|clang)[^\x00\r\n]{0,240}(?:clang|Clang)[^\x00\r\n]{0,240})",
    )
    config_bytes = extract_ikconfig(kernel)
    if config_bytes is None and not args.allow_missing_ikconfig:
        raise SystemExit("embedded IKCONFIG was not found")

    config_path: Path | None = None
    parsed_config: dict[str, str] = {}
    if config_bytes is not None:
        config_hash = sha256_bytes(config_bytes)
        if config_hash != EXPECTED_IKCONFIG_SHA256:
            raise SystemExit(
                "IKCONFIG SHA-256 mismatch: "
                f"{config_hash} != {EXPECTED_IKCONFIG_SHA256}"
            )
        parsed_config = parse_config(config_bytes)

    output_dir = args.output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    kernel_path = output_dir / "kernel"
    ramdisk_path = output_dir / "ramdisk.cpio"
    config_path = output_dir / "kernel.config" if config_bytes is not None else None
    metadata_path = output_dir / "boot-profile.json"
    destinations = [kernel_path, metadata_path]
    if ramdisk_size:
        destinations.append(ramdisk_path)
    if config_path is not None:
        destinations.append(config_path)
    if not args.force:
        existing = [path for path in destinations if path.exists()]
        if existing:
            raise FileExistsError(
                "refusing to overwrite existing output(s): "
                + ", ".join(str(path) for path in existing)
                + "; pass --force"
            )

    write_bytes(kernel_path, kernel, force=args.force)
    if ramdisk_size:
        write_bytes(ramdisk_path, ramdisk, force=args.force)
    if config_path is not None and config_bytes is not None:
        write_bytes(config_path, config_bytes, force=args.force)

    metadata = {
        "target": "oneplus-pad3",
        "source": {
            "path": str(boot_image),
            "size": boot_size,
            "sha256": boot_hash,
        },
        "boot_header": {
            "version": header_version,
            "header_size": header_size,
            "alignment": BOOT_ALIGNMENT,
            "os_version_raw": os_version,
            "kernel_offset": kernel_offset,
            "kernel_size": kernel_size,
            "ramdisk_offset": ramdisk_offset,
            "ramdisk_size": ramdisk_size,
            "signature_offset": signature_offset,
            "signature_size": signature_size,
        },
        "kernel": {
            "path": kernel_path.name,
            "size": kernel_path.stat().st_size,
            "sha256": kernel_hash,
            "release": kernel_release,
            "linux_version": linux_version,
            "compiler": compiler,
            "kmi": "android15-6.6",
        },
        "ikconfig": {
            "path": config_path.name if config_path else None,
            "sha256": sha256_bytes(config_bytes) if config_bytes is not None else None,
            "facts": config_profile(parsed_config),
        },
        "resolved_target_profile": {
            "btf_struct_offsets": "exact Image BTF",
            "kallsyms_symbol_offsets": "exact embedded kallsyms",
            "pselect_stack": {
                "status": "exact-static-disassembly-verified",
                "stack_fds_from_syscall_sp": "-0x200",
                "waiter_from_syscall_sp": "-0x200",
                "pselect_waiter_word_shift": -2,
            },
            "ashmem_route": {
                "type": "c-static-miscdevice",
                "ashmem_misc_offset": "0x0227c518",
                "miscdevice_fops_offset": "0x10",
                "ashmem_misc_fops_offset": "0x0227c528",
                "preferred_root_route": "configfs-pipe-physrw-fcred-stop-pidfd-guardian-legit-commit-sealed-execveat",
            },
        },
        "physical_layout": {
            "phys_offset": "0x80000000",
            "kernel_phys_load_candidate": "0xa8000000",
            "status": "exact-xbl-candidate-pending-runtime-readback",
        },
        "unresolved": ["kernel_phys_load_runtime_readback"],
    }
    write_bytes(
        metadata_path,
        (json.dumps(metadata, indent=2, sort_keys=True) + "\n").encode(),
        force=args.force,
    )

    print(f"boot      {boot_size} {boot_hash}")
    print(f"header    v{header_version} size={header_size} alignment={BOOT_ALIGNMENT}")
    print(f"kernel    {kernel_size} {metadata['kernel']['sha256']}")
    print(f"release   {kernel_release}")
    print(f"ramdisk   {ramdisk_size}")
    print(f"ikconfig  {'extracted' if config_bytes is not None else 'not found'}")
    print(f"profile   {metadata_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileExistsError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
