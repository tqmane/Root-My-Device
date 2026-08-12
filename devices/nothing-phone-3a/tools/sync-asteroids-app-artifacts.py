#!/usr/bin/env python3
"""Install freshly built Asteroids native artifacts into the Android app.

The app pins byte size + SHA-256 for all three native components.  This script
copies a freshly built payload/helper/ksud and rewrites those pins atomically,
then writes the stamp required by Gradle.  It exists so a source change to the
late-load helper or ksud cannot accidentally produce an APK carrying an older
binary with a still-valid old hash.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_NATIVE = ROOT / "build/asteroids_jp_6.1.157-android14-11-g82d681c9b06b-ab14634535"
DEFAULT_KSUD = ROOT / "build/asteroids-fixed/ksud-asteroids"
ARTIFACT_STORE = ROOT / "app/src/main/java/dev/tqmane/rootmynothing/ArtifactStore.kt"
ASSETS = ROOT / "app/src/main/assets"
JNI = ROOT / "app/src/main/jniLibs/arm64-v8a"
STAMP = ASSETS / ".asteroids-artifacts-synced"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def require_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise SystemExit(f"{label} not found: {path}")


def replace_once(text: str, pattern: str, replacement: str, label: str) -> str:
    new, n = re.subn(pattern, replacement, text, count=1, flags=re.S)
    if n != 1:
        raise SystemExit(f"could not update {label} in {ARTIFACT_STORE}")
    return new


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--payload", type=Path, default=DEFAULT_NATIVE / "cve-2026-43499-standalone")
    ap.add_argument("--helper", type=Path, default=DEFAULT_NATIVE / "cve-2026-43499-root")
    ap.add_argument("--ksud", type=Path, default=DEFAULT_KSUD)
    args = ap.parse_args()

    for path, label in [(args.payload, "payload"), (args.helper, "helper"), (args.ksud, "ksud")]:
        require_file(path, label)

    ASSETS.mkdir(parents=True, exist_ok=True)
    JNI.mkdir(parents=True, exist_ok=True)
    payload_dst = ASSETS / "cve-2026-43499-standalone"
    ksud_dst = ASSETS / "ksud-asteroids"
    helper_dst = JNI / "libcve43499root.so"

    for src, dst in [(args.payload, payload_dst), (args.ksud, ksud_dst), (args.helper, helper_dst)]:
        tmp = dst.with_suffix(dst.suffix + ".tmp")
        shutil.copy2(src, tmp)
        tmp.replace(dst)

    payload_size, payload_hash = payload_dst.stat().st_size, sha256(payload_dst)
    ksud_size, ksud_hash = ksud_dst.stat().st_size, sha256(ksud_dst)
    helper_size, helper_hash = helper_dst.stat().st_size, sha256(helper_dst)

    text = ARTIFACT_STORE.read_text()
    text = replace_once(
        text,
        r'(source = "cve-2026-43499-standalone",.*?size = )[0-9_]+(,\s*sha256 = ")[0-9a-f]+(")',
        rf'\g<1>{payload_size:_}\g<2>{payload_hash}\g<3>',
        "payload pin",
    )
    text = replace_once(
        text,
        r'(source = "ksud-asteroids",.*?size = )[0-9_]+(,\s*sha256 = ")[0-9a-f]+(")',
        rf'\g<1>{ksud_size:_}\g<2>{ksud_hash}\g<3>',
        "ksud pin",
    )
    text = replace_once(
        text,
        r'(private const val HELPER_SIZE = )[0-9_]+L(\s*private const val HELPER_SHA256 =\s*")[0-9a-f]+(")',
        rf'\g<1>{helper_size:_}L\g<2>{helper_hash}\g<3>',
        "helper pin",
    )
    ARTIFACT_STORE.write_text(text)

    STAMP.write_text(
        "target=asteroids\n"
        "kernel_release=6.1.157-android14-11-g82d681c9b06b-ab14634535\n"
        "source_fix=1.2.0\n"
        f"payload={payload_size} {payload_hash}\n"
        f"ksud={ksud_size} {ksud_hash}\n"
        f"helper={helper_size} {helper_hash}\n"
    )
    print(f"payload {payload_size} {payload_hash}")
    print(f"ksud    {ksud_size} {ksud_hash}")
    print(f"helper  {helper_size} {helper_hash}")
    print(f"updated {ARTIFACT_STORE.relative_to(ROOT)}")
    print(f"wrote   {STAMP.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
