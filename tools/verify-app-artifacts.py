#!/usr/bin/env python3
"""Verify the immutable native artifacts embedded in both Android projects."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
IDENTITY_RE = re.compile(r"([0-9]+) ([0-9a-f]{64})")


@dataclass(frozen=True)
class Project:
    label: str
    root: Path
    stamp_name: str
    ksud_name: str
    artifact_store: Path
    expected_stamp: dict[str, str]
    require_embedded_chain: bool = False


PROJECTS = (
    Project(
        label="Nothing Phone (3a)",
        root=ROOT / "devices/nothing-phone-3a",
        stamp_name=".asteroids-artifacts-synced",
        ksud_name="ksud-asteroids",
        artifact_store=Path("dev/tqmane/rootmynothing/ArtifactStore.kt"),
        expected_stamp={
            "target": "asteroids",
            "kernel_release": "6.1.157-android14-11-g82d681c9b06b-ab14634535",
            "source_fix": "1.2.0",
        },
    ),
    Project(
        label="OnePlus Pad 3",
        root=ROOT / "devices/oneplus-pad-3",
        stamp_name=".oneplus-pad3-artifacts-synced",
        ksud_name="ksud-oneplus-pad3",
        artifact_store=Path("dev/tqmane/rootmyonepluspad3/ArtifactStore.kt"),
        expected_stamp={
            "target": "oneplus-pad3",
            "kernel_release": "6.6.118-android15-8-g2e6b9c3812c5-ab15114928-4k",
        },
        require_embedded_chain=True,
    ),
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def identity(path: Path) -> tuple[int, str]:
    if not path.is_file():
        raise ValueError(f"missing artifact: {path.relative_to(ROOT)}")
    return path.stat().st_size, sha256(path)


def parse_stamp(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise ValueError(f"missing artifact stamp: {path.relative_to(ROOT)}")
    values: dict[str, str] = {}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line:
            continue
        if "=" not in line:
            raise ValueError(f"malformed stamp line {path.relative_to(ROOT)}:{line_number}")
        key, value = line.split("=", 1)
        if key in values:
            raise ValueError(f"duplicate stamp key {key!r} in {path.relative_to(ROOT)}")
        values[key] = value
    return values


def parse_identity(value: str, label: str) -> tuple[int, str]:
    match = IDENTITY_RE.fullmatch(value)
    if match is None:
        raise ValueError(f"malformed size/SHA-256 identity for {label}: {value!r}")
    return int(match.group(1)), match.group(2)


def parse_store_pins(
    path: Path,
    payload_name: str,
    ksud_name: str,
) -> dict[str, tuple[int, str]]:
    text = path.read_text(encoding="utf-8")

    def asset_pin(source: str) -> tuple[int, str]:
        match = re.search(
            rf'source\s*=\s*"{re.escape(source)}",[\s\S]*?'
            rf'size\s*=\s*([0-9_]+),\s*sha256\s*=\s*"([0-9a-f]{{64}})"',
            text,
        )
        if match is None:
            raise ValueError(f"ArtifactStore has no complete pin for {source}: {path}")
        return int(match.group(1).replace("_", "")), match.group(2)

    helper = re.search(
        r'HELPER_SIZE\s*=\s*([0-9_]+)L[\s\S]*?'
        r'HELPER_SHA256\s*=\s*"([0-9a-f]{64})"',
        text,
    )
    if helper is None:
        raise ValueError(f"ArtifactStore has no complete helper pin: {path}")

    return {
        "payload": asset_pin(payload_name),
        "ksud": asset_pin(ksud_name),
        "helper": (int(helper.group(1).replace("_", "")), helper.group(2)),
    }


def verify_aarch64_elf(path: Path) -> None:
    header = path.read_bytes()[:64]
    if len(header) < 20 or header[:4] != b"\x7fELF":
        raise ValueError(f"artifact is not ELF: {path.relative_to(ROOT)}")
    if header[4] != 2 or header[5] != 1:
        raise ValueError(f"artifact is not little-endian ELF64: {path.relative_to(ROOT)}")
    machine = struct.unpack_from("<H", header, 18)[0]
    if machine != 183:  # EM_AARCH64
        raise ValueError(
            f"artifact has e_machine={machine}, expected AArch64: {path.relative_to(ROOT)}"
        )


def count_ascii(path: Path, value: str) -> int:
    return path.read_bytes().count(value.encode("ascii"))


def verify_project(project: Project) -> list[str]:
    main = project.root / "app/src/main"
    artifacts = {
        "payload": main / "assets/cve-2026-43499-standalone",
        "ksud": main / f"assets/{project.ksud_name}",
        "helper": main / "jniLibs/arm64-v8a/libcve43499root.so",
    }
    stamp = parse_stamp(main / f"assets/{project.stamp_name}")

    for key, expected in project.expected_stamp.items():
        actual = stamp.get(key)
        if actual != expected:
            raise ValueError(
                f"{project.label} stamp {key} mismatch: {actual!r} != {expected!r}"
            )

    actual_identities = {name: identity(path) for name, path in artifacts.items()}
    stamped_identities = {
        name: parse_identity(stamp.get(name, ""), f"{project.label} {name}")
        for name in artifacts
    }
    if actual_identities != stamped_identities:
        raise ValueError(
            f"{project.label} artifact files do not match {project.stamp_name}"
        )

    store = main / "java" / project.artifact_store
    store_identities = parse_store_pins(
        store,
        "cve-2026-43499-standalone",
        project.ksud_name,
    )
    if actual_identities != store_identities:
        raise ValueError(f"{project.label} artifact files do not match ArtifactStore.kt")

    for path in artifacts.values():
        verify_aarch64_elf(path)

    if project.require_embedded_chain:
        ksud_hash = actual_identities["ksud"][1]
        helper_hash = actual_identities["helper"][1]
        helper_count = count_ascii(artifacts["helper"], ksud_hash)
        payload_count = count_ascii(artifacts["payload"], helper_hash)
        if helper_count != 1:
            raise ValueError(
                f"{project.label} helper -> ksud digest occurrence count is {helper_count}, expected 1"
            )
        if payload_count != 1:
            raise ValueError(
                f"{project.label} payload -> helper digest occurrence count is {payload_count}, expected 1"
            )

    lines = [project.label]
    for name, (size, digest) in actual_identities.items():
        lines.append(f"  {name}: {size} bytes {digest}")
    if "kernelsu" in stamp:
        parse_identity(stamp["kernelsu"], f"{project.label} kernelsu")
        lines.append(f"  kernelsu source: {stamp['kernelsu']}")
    return lines


def main() -> int:
    try:
        lines: list[str] = []
        for project in PROJECTS:
            lines.extend(verify_project(project))
    except (OSError, ValueError) as error:
        print(f"App artifact verification failed: {error}", file=sys.stderr)
        return 1

    print("\n".join(lines))
    print(
        "App artifact verification passed: stamps, Kotlin pins, AArch64 ELF "
        "identity, and required embedded hash links match."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
