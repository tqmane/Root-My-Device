#!/usr/bin/env python3
"""Synchronize freshly built OnePlus Pad 3 artifacts and their hash pins.

The KernelSU module is embedded in ksud rather than copied into the APK as a
second payload.  Its hash is still recorded in the Gradle stamp so the four
outputs that form one build are auditable together.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_MONOREPO_CANDIDATE = ROOT.parent.parent
REPOSITORY_ROOT = (
    _MONOREPO_CANDIDATE
    if (_MONOREPO_CANDIDATE / "src/kernelsu/Root-My-Device-KSU").exists()
    else ROOT
)
PATCH_SUBMODULE = REPOSITORY_ROOT / "src/kernelsu/Root-My-Device-KSU"
KERNEL_RELEASE = "6.6.118-android15-8-g2e6b9c3812c5-ab15114928-4k"
TARGET = f"oneplus-pad3/ex/{KERNEL_RELEASE}"
TARGET_SLUG = TARGET.replace("/", "_")
DEFAULT_NATIVE = ROOT / "build" / TARGET_SLUG
DEFAULT_WORK = ROOT / "build/oneplus-pad3-fixed"
ARTIFACT_STORE = (
    ROOT / "app/src/main/java/dev/tqmane/rootmyonepluspad3/ArtifactStore.kt"
)
ASSETS = ROOT / "app/src/main/assets"
JNI = ROOT / "app/src/main/jniLibs/arm64-v8a"
STAMP = ASSETS / ".oneplus-pad3-artifacts-synced"
LEGACY_ASSETS = (
    ASSETS / ".asteroids-artifacts-synced",
    ASSETS / "ksud-asteroids",
)


@dataclass(frozen=True)
class Artifact:
    name: str
    source: Path
    destination: Path | None
    size: int
    digest: str


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_file(path: Path, label: str) -> Path:
    path = path.expanduser().resolve()
    if not path.is_file():
        raise SystemExit(f"{label} not found: {path}")
    if path.stat().st_size <= 0:
        raise SystemExit(f"{label} is empty: {path}")
    return path


def artifact(name: str, source: Path, destination: Path | None) -> Artifact:
    source = require_file(source, name)
    return Artifact(name, source, destination, source.stat().st_size, sha256(source))


def require_exact_ascii_pin(
    container: Artifact, pinned: Artifact, relationship: str
) -> None:
    """Require the build-time digest contract to survive in the shipped ELF."""
    occurrences = container.source.read_bytes().count(pinned.digest.encode("ascii"))
    if occurrences != 1:
        raise SystemExit(
            f"{relationship} is not exact: expected one ASCII {pinned.name} "
            f"SHA-256 pin in {container.source}, found {occurrences}"
        )


def replace_once(text: str, pattern: str, replacement: str, label: str) -> str:
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.S)
    if count != 1:
        raise SystemExit(f"could not update {label} in {ARTIFACT_STORE}")
    return updated


def newest_source_mtime(paths: list[Path], suffixes: set[str]) -> tuple[int, Path] | None:
    newest: tuple[int, Path] | None = None
    for root in paths:
        if not root.exists():
            continue
        candidates = [root] if root.is_file() else root.rglob("*")
        for candidate in candidates:
            if not candidate.is_file() or candidate.suffix not in suffixes:
                continue
            current = (candidate.stat().st_mtime_ns, candidate)
            if newest is None or current[0] > newest[0]:
                newest = current
    return newest


def enforce_freshness(
    built: list[Artifact],
    sources: list[Path],
    suffixes: set[str],
    label: str,
) -> None:
    newest = newest_source_mtime(sources, suffixes)
    if newest is None:
        return
    source_time, source_path = newest
    for item in built:
        if item.source.stat().st_mtime_ns < source_time:
            raise SystemExit(
                f"stale {item.name}: {item.source} is older than {source_path}; "
                f"rebuild the {label} outputs (or pass --allow-stale only for a "
                "reproducible build whose timestamps are known to be synthetic)"
            )


def update_artifact_store(text: str, items: dict[str, Artifact]) -> str:
    payload = items["payload"]
    ksud = items["ksud"]
    helper = items["helper"]
    text = replace_once(
        text,
        r'(source = "cve-2026-43499-standalone",.*?size = )[0-9_]+(,\s*sha256 = ")[0-9a-f]+(")',
        rf"\g<1>{payload.size:_}\g<2>{payload.digest}\g<3>",
        "payload pin",
    )
    text = replace_once(
        text,
        r'(source = "ksud-oneplus-pad3",.*?size = )[0-9_]+(,\s*sha256 = ")[0-9a-f]+(")',
        rf"\g<1>{ksud.size:_}\g<2>{ksud.digest}\g<3>",
        "ksud pin",
    )
    return replace_once(
        text,
        r'(private const val HELPER_SIZE = )[0-9_]+L(\s*private const val HELPER_SHA256 =\s*")[0-9a-f]+(")',
        rf"\g<1>{helper.size:_}L\g<2>{helper.digest}\g<3>",
        "helper pin",
    )


def stamp_text(items: dict[str, Artifact]) -> str:
    return "".join(
        [
            "target=oneplus-pad3\n",
            f"kernel_release={KERNEL_RELEASE}\n",
            *(
                f"{name}={items[name].size} {items[name].digest}\n"
                for name in ("payload", "ksud", "helper", "kernelsu")
            ),
        ]
    )


def atomic_copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
    try:
        shutil.copy2(source, temporary)
        if temporary.stat().st_size != source.stat().st_size or sha256(temporary) != sha256(source):
            raise SystemExit(f"copy verification failed: {source} -> {destination}")
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def check_synced(items: dict[str, Artifact], expected_store: str, expected_stamp: str) -> None:
    failures: list[str] = []
    for item in items.values():
        if item.destination is None:
            continue
        if not item.destination.is_file():
            failures.append(f"missing destination: {item.destination}")
            continue
        if item.destination.stat().st_size != item.size or sha256(item.destination) != item.digest:
            failures.append(f"destination mismatch: {item.destination}")
    if not ARTIFACT_STORE.is_file() or ARTIFACT_STORE.read_text(encoding="utf-8") != expected_store:
        failures.append(f"pins do not match: {ARTIFACT_STORE}")
    if not STAMP.is_file() or STAMP.read_text(encoding="utf-8") != expected_stamp:
        failures.append(f"stamp does not match: {STAMP}")
    for legacy in LEGACY_ASSETS:
        if legacy.exists():
            failures.append(f"legacy Asteroids asset remains: {legacy}")
    if failures:
        raise SystemExit("artifact synchronization check failed:\n  " + "\n  ".join(failures))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Copy exact Pad 3 payloads into the app and update hash pins"
    )
    parser.add_argument(
        "--payload",
        type=Path,
        default=DEFAULT_NATIVE / "cve-2026-43499-standalone",
    )
    parser.add_argument(
        "--helper",
        type=Path,
        default=DEFAULT_NATIVE / "cve-2026-43499-root",
    )
    parser.add_argument("--ksud", type=Path, default=DEFAULT_WORK / "ksud-oneplus-pad3")
    parser.add_argument(
        "--module",
        type=Path,
        default=DEFAULT_WORK / "KernelSU/kernel/kernelsu.ko",
        help="the module embedded into ksud; hashed in the stamp but not copied twice",
    )
    parser.add_argument("--check", action="store_true", help="verify without modifying files")
    parser.add_argument(
        "--allow-stale",
        action="store_true",
        help="allow artifacts with mtimes older than their relevant sources",
    )
    args = parser.parse_args()

    if not ARTIFACT_STORE.is_file():
        raise SystemExit(f"ArtifactStore not found: {ARTIFACT_STORE}")

    items = {
        "payload": artifact(
            "payload", args.payload, ASSETS / "cve-2026-43499-standalone"
        ),
        "helper": artifact("helper", args.helper, JNI / "libcve43499root.so"),
        "ksud": artifact("ksud", args.ksud, ASSETS / "ksud-oneplus-pad3"),
        "kernelsu": artifact("kernelsu", args.module, None),
    }
    require_exact_ascii_pin(items["helper"], items["ksud"], "helper -> ksud pin")
    require_exact_ascii_pin(items["payload"], items["helper"], "payload -> helper pin")

    if not args.allow_stale:
        enforce_freshness(
            [items["payload"], items["helper"]],
            [
                ROOT / "src/payloads/CVE-2026-43499",
                ROOT / "src/payloads/su_daemon",
                ROOT / "src/targets/oneplus-pad3/ex" / KERNEL_RELEASE,
                ROOT / "Makefile",
            ],
            {"", ".c", ".h", ".S", ".json", ".mk"},
            "native",
        )
        enforce_freshness(
            [items["kernelsu"]],
            [
                DEFAULT_WORK / "KernelSU/kernel",
                PATCH_SUBMODULE / "patches/32525/common",
                PATCH_SUBMODULE / "patches/32525/devices/oneplus-pad3",
            ],
            {".c", ".h", ".mk", ".patch"},
            "KernelSU module",
        )
        enforce_freshness(
            [items["ksud"]],
            [
                DEFAULT_WORK / "KernelSU/userspace",
                DEFAULT_WORK / "KernelSU/Cargo.toml",
                items["kernelsu"].source,
                PATCH_SUBMODULE / "patches/32525/common",
                PATCH_SUBMODULE / "patches/32525/devices/oneplus-pad3",
            ],
            {".rs", ".toml", ".patch", ".ko"},
            "ksud",
        )

    original_store = ARTIFACT_STORE.read_text(encoding="utf-8")
    expected_store = update_artifact_store(original_store, items)
    expected_stamp = stamp_text(items)

    if args.check:
        check_synced(items, expected_store, expected_stamp)
        print("OnePlus Pad 3 artifacts and pins are synchronized")
        return 0

    for item in items.values():
        if item.destination is not None:
            atomic_copy(item.source, item.destination)
    atomic_write(ARTIFACT_STORE, expected_store)
    atomic_write(STAMP, expected_stamp)
    for legacy in LEGACY_ASSETS:
        legacy.unlink(missing_ok=True)
    check_synced(items, expected_store, expected_stamp)

    for name in ("payload", "ksud", "helper", "kernelsu"):
        item = items[name]
        print(f"{name:9} {item.size} {item.digest}")
    print(f"updated   {ARTIFACT_STORE.relative_to(ROOT)}")
    print(f"wrote     {STAMP.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
