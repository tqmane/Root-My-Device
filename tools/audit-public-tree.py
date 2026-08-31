#!/usr/bin/env python3
"""Fail closed on public-tree, target-isolation, and Git hygiene regressions."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]

EXPECTED_ORIGIN = "https://github.com/tqmane/Root-My-Device"
PINNED_SUBMODULES = {
    Path("src/kernelsu/KernelSU"): "932014ab5b2c9b74a3d11e2ec4d17dd10fc9442e",
}
REQUIRED_SUBMODULE_PATHS = {
    Path("src/kernelsu/KernelSU"),
    Path("src/kernelsu/Root-My-Device-KSU"),
}
EXPECTED_SUBMODULE_URLS = {
    Path("src/kernelsu/KernelSU"): "https://github.com/tiann/KernelSU.git",
    Path("src/kernelsu/Root-My-Device-KSU"): "https://github.com/tqmane/Root-My-Device-KSU.git",
}

EXPECTED_EXECUTABLES = {
    Path("devices/nothing-phone-3a/gradlew"),
    Path("devices/nothing-phone-3a/diagnostics/asteroids/kick-blocked-reason.sh"),
    Path("devices/nothing-phone-3a/diagnostics/asteroids/late-load-modules.sh"),
    Path("devices/nothing-phone-3a/diagnostics/asteroids/run-on-device.sh"),
    Path("devices/nothing-phone-3a/tools/build-asteroids-fixed.sh"),
    Path("devices/nothing-phone-3a/tools/kernel/build-ddk-module.sh"),
    Path("devices/nothing-phone-3a/tools/sync-asteroids-app-artifacts.py"),
    Path("devices/oneplus-pad-3/gradlew"),
    Path("devices/oneplus-pad-3/diagnostics/oneplus-pad3/late-load-oneplus-pad3.sh"),
    Path("devices/oneplus-pad-3/tools/build-oneplus-pad3.sh"),
    Path("devices/oneplus-pad-3/tools/extract-boot.py"),
    Path("devices/oneplus-pad-3/tools/kernel/build-ddk-module.sh"),
    Path("devices/oneplus-pad-3/tools/sync-oneplus-pad3-app-artifacts.py"),
    Path("devices/oneplus-pad-3/tools/verify-pad3-reclaim-binary.py"),
    Path("devices/oneplus-pad-3/tools/verify-profile.py"),
    Path("devices/oneplus-pad-3/tools/verify-target.py"),
    Path("tools/audit-public-tree.py"),
    Path("tools/build-all.sh"),
    Path("tools/check-json-files.py"),
    Path("tools/verify-app-artifacts.py"),
}

NOTHING_ROOT = Path("devices/nothing-phone-3a")
ONEPLUS_ROOT = Path("devices/oneplus-pad-3")
EXPECTED_DEVICE_ROOTS = {NOTHING_ROOT, ONEPLUS_ROOT}

EXPECTED_PROFILES = {
    NOTHING_ROOT: {
        "profileId": "asteroids-jp-B4.1-260618-1048",
        "core": "core61",
        "model": "A059",
        "device": "asteroids",
        "buildDisplay": "B4.1-260618-1048",
        "buildFingerprint": (
            "Nothing/AsteroidsJPN/Asteroids:16/BQ2A.250721.001-"
            "BP2A.250605.031.A3/2606181048:user/release-keys"
        ),
        "securityPatch": "2026-06-01",
        "sdk": 36,
        "kernelRelease": "6.1.157-android14-11-g82d681c9b06b-ab14634535",
        "abi": "arm64-v8a",
        "pageSize": 4096,
    },
    ONEPLUS_ROOT: {
        "profileId": "oneplus-pad3-ex-16.0.9.400",
        "core": "core66",
        "model": "OPD2415",
        "device": "oneplus-pad3",
        "deviceProperty": "OP6190L1",
        "product": "OPD2415IN",
        "buildDisplay": "OPD2415_16.0.9.400(EX01)",
        "buildFingerprint": (
            "OnePlus/OPD2415IN/OP6190L1:16/AP3A.240617.008/"
            "V.R4T3.17bf73d_cf42a1_c9913b:user/release-keys"
        ),
        "securityPatch": "2026-07-01",
        "sdk": 36,
        "kernelRelease": "6.6.118-android15-8-g2e6b9c3812c5-ab15114928-4k",
        "abi": "arm64-v8a",
        "pageSize": 4096,
    },
}

EXPECTED_TARGET_DIRS = {
    NOTHING_ROOT
    / "src/targets/asteroids/jp/6.1.157-android14-11-g82d681c9b06b-ab14634535",
    ONEPLUS_ROOT
    / "src/targets/oneplus-pad3/ex/6.6.118-android15-8-g2e6b9c3812c5-ab15114928-4k",
}
EXPECTED_CORE_DIRS = {
    NOTHING_ROOT / "src/payloads/CVE-2026-43499/core61",
    ONEPLUS_ROOT / "src/payloads/CVE-2026-43499/core66",
}

GRADLE_DISTRIBUTION_URL = (
    r"https\://services.gradle.org/distributions/gradle-9.5.1-bin.zip"
)
GRADLE_DISTRIBUTION_SHA256 = (
    "bafc141b619ad6350fd975fc903156dd5c151998cc8b058e8c1044ab5f7b031f"
)
GRADLE_WRAPPER_JAR_SHA256 = (
    "497c8c2a7e5031f6aa847f88104aa80a93532ec32ee17bdb8d1d2f67a194a9c7"
)

# Required source provenance recorded outside the imported private histories.
EXPECTED_SOURCE_PROVENANCE = {
    "devices/nothing-phone-3a": "58df2d94cb907b589eef5f26f21f214a249c85b8",
    "devices/oneplus-pad-3": "ff7294631fce27e5cf0a345346dc16bb04d2412b",
}

# Private workstation/credential indicators. Project names and public noreply
# identities are deliberately not forbidden.
FORBIDDEN_BYTES = {
    b"/home/" + b"tqmane/": "private Linux home path",
    b"nomu78" + b"@" + b"iwink.jp": "private email address",
    b"film" + b"_sims": "unrelated private signing identity",
    b"C:" + b"\\Users\\": "Windows absolute user path",
    b"BEGIN " + b"PRIVATE KEY": "private key material",
    b"BEGIN RSA " + b"PRIVATE KEY": "RSA private key material",
    b"github" + b"_pat_": "GitHub token prefix",
    b"gh" + b"p_": "GitHub token prefix",
    b"AIza" + b"Sy": "Google API key prefix",
}

CREDENTIAL_SUFFIXES = {
    ".jks", ".keystore", ".p12", ".pfx", ".pem", ".key", ".der",
    ".password", ".passwords",
}
BINARY_SUFFIXES = {
    ".apk", ".aab", ".apks", ".img", ".jar", ".ko", ".so", ".zip",
    *CREDENTIAL_SUFFIXES,
}
CRLF_ALLOWED_SUFFIXES = {".bat"}


def normalize_git_url(value: str) -> str:
    value = value.strip().rstrip("/")
    return value[:-4] if value.endswith(".git") else value


def run_at(repo: Path, *args: str, text: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        cwd=repo,
        check=False,
        capture_output=True,
        text=text,
    )


def run(*args: str, text: bool = True) -> subprocess.CompletedProcess:
    return run_at(ROOT, *args, text=text)


def tracked_entries(repo: Path = ROOT) -> list[tuple[str, str, Path]]:
    result = run_at(repo, "git", "ls-files", "--stage", "-z", text=False)
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors="replace").strip())
    entries: list[tuple[str, str, Path]] = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        metadata, name = raw.split(b"\t", 1)
        mode, oid, _stage = metadata.decode("ascii").split(" ")
        entries.append((mode, oid, Path(os.fsdecode(name))))
    return entries


def is_probably_text(path: Path, data: bytes) -> bool:
    if path.suffix.lower() in BINARY_SUFFIXES:
        return False
    return b"\0" not in data[:8192]


def scan_forbidden(data: bytes, label: str, errors: list[str]) -> None:
    for needle, description in FORBIDDEN_BYTES.items():
        if needle in data:
            errors.append(f"{label} contains {description}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_git_dir(repo: Path) -> Path | None:
    result = run_at(repo, "git", "rev-parse", "--absolute-git-dir")
    if result.returncode:
        return None
    return Path(result.stdout.strip())


def audit_git_repository(
    repo: Path,
    label: str,
    errors: list[str],
    *,
    scan_history: bool = True,
) -> None:
    history = run_at(
        repo,
        "git",
        "log",
        "--all",
        "--format=%an%x00%ae%x00%cn%x00%ce%x00%B%x00",
        text=False,
    )
    if history.returncode:
        errors.append(f"unable to inspect {label} Git history")
    elif scan_history:
        scan_forbidden(history.stdout, f"{label} Git history", errors)

    config = run_at(repo, "git", "config", "--local", "--null", "--list", text=False)
    if config.returncode == 0:
        scan_forbidden(config.stdout, f"{label} local Git config", errors)

    git_dir = resolve_git_dir(repo)
    if git_dir is None:
        errors.append(f"unable to resolve {label} Git directory")
        return
    for relative in (Path("config"), Path("packed-refs")):
        path = git_dir / relative
        if path.is_file():
            scan_forbidden(path.read_bytes(), f"{label} {relative}", errors)
    logs = git_dir / "logs"
    if logs.is_dir():
        for path in logs.rglob("*"):
            if path.is_file():
                scan_forbidden(path.read_bytes(), f"{label} {path.relative_to(git_dir)}", errors)

    fsck = run_at(repo, "git", "fsck", "--full", "--no-progress")
    if fsck.returncode:
        errors.append(
            f"{label} git fsck failed: "
            f"{fsck.stdout.strip() or fsck.stderr.strip()}"
        )


def audit_submodule_worktree(
    relative: Path,
    expected_head: str,
    errors: list[str],
) -> None:
    repo = ROOT / relative
    # CI may intentionally leave submodules uninitialized. A normal checkout
    # can leave an empty gitlink directory, so require submodule-local Git
    # metadata before treating the directory as an initialized worktree.
    if not (repo / ".git").exists():
        return
    probe = run_at(repo, "git", "rev-parse", "--is-inside-work-tree")
    if probe.returncode or probe.stdout.strip() != "true":
        errors.append(f"initialized submodule is not a valid worktree: {relative}")
        return
    head = run_at(repo, "git", "rev-parse", "HEAD")
    if head.returncode or head.stdout.strip() != expected_head:
        errors.append(
            f"{relative} worktree HEAD mismatch: "
            f"{head.stdout.strip() or 'unknown'} != {expected_head}"
        )
    status = run_at(repo, "git", "status", "--porcelain")
    if status.returncode or status.stdout.strip():
        errors.append(f"{relative} submodule worktree is dirty")

    try:
        entries = tracked_entries(repo)
    except Exception as error:
        errors.append(f"unable to enumerate {relative}: {error}")
        entries = []

    for mode, _oid, child in entries:
        if mode == "160000":
            errors.append(f"unexpected nested submodule in {relative}: {child}")
            continue
        path = repo / child
        if mode == "120000" or not path.is_file():
            continue
        scan_forbidden(path.read_bytes(), f"submodule {relative}/{child}", errors)

    if relative.name == "Root-My-Device-KSU":
        common = [
            child for _mode, _oid, child in entries
            if child.parent == Path("patches/32601/common") and child.suffix == ".patch"
        ]
        asteroids = [
            child for _mode, _oid, child in entries
            if child.parent == Path("patches/32601/devices/asteroids")
            and child.suffix == ".patch"
        ]
        oneplus = [
            child for _mode, _oid, child in entries
            if child.parent == Path("patches/32601/devices/oneplus-pad3")
            and child.suffix == ".patch"
        ]
        expected_counts = {"common": 6, "asteroids": 3, "oneplus-pad3": 13}
        actual_counts = {
            "common": len(common),
            "asteroids": len(asteroids),
            "oneplus-pad3": len(oneplus),
        }
        if actual_counts != expected_counts:
            errors.append(
                "Root-My-Device-KSU required patch counts mismatch: "
                f"{actual_counts} != {expected_counts}"
            )

    # Root-My-Device-KSU is pinned by the parent repository gitlink. Its exact
    # commit can advance when the maintained 32601 device patch port advances,
    # so the audit compares the initialized worktree to that gitlink instead of
    # baking a second copy of the SHA into this script.
    audit_git_repository(
        repo,
        f"submodule {relative}",
        errors,
        scan_history=relative.name != "Root-My-Device-KSU",
    )


def audit_profiles(errors: list[str]) -> None:
    for device_root, expected in EXPECTED_PROFILES.items():
        path = ROOT / device_root / "src/targets.json"
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except Exception as error:
            errors.append(f"unable to parse {path.relative_to(ROOT)}: {error}")
            continue
        targets = document.get("targets")
        if not isinstance(targets, list) or len(targets) != 1:
            errors.append(f"{path.relative_to(ROOT)} must contain exactly one target")
            continue
        target = targets[0]
        for key, value in expected.items():
            if target.get(key) != value:
                errors.append(
                    f"{path.relative_to(ROOT)} {key} mismatch: "
                    f"{target.get(key)!r} != {value!r}"
                )


def audit_device_isolation(errors: list[str]) -> None:
    actual_device_roots = {
        path.relative_to(ROOT)
        for path in (ROOT / "devices").iterdir()
        if path.is_dir()
    }
    if actual_device_roots != EXPECTED_DEVICE_ROOTS:
        errors.append(
            "device directory set mismatch: "
            f"{sorted(map(str, actual_device_roots))}"
        )

    for path in EXPECTED_TARGET_DIRS | EXPECTED_CORE_DIRS:
        if not (ROOT / path).is_dir():
            errors.append(f"missing exact device path: {path}")

    forbidden_cross_paths = {
        NOTHING_ROOT / "src/payloads/CVE-2026-43499/core66",
        NOTHING_ROOT / "src/targets/oneplus-pad3",
        ONEPLUS_ROOT / "src/payloads/CVE-2026-43499/core61",
        ONEPLUS_ROOT / "src/targets/asteroids",
    }
    for path in forbidden_cross_paths:
        if (ROOT / path).exists():
            errors.append(f"cross-device target/core remains: {path}")

    for device_root in EXPECTED_DEVICE_ROOTS:
        for forbidden in (".git", ".gitmodules", ".github"):
            if (ROOT / device_root / forbidden).exists():
                errors.append(f"nested repository metadata remains: {device_root / forbidden}")

    expected_assets = {
        NOTHING_ROOT: {
            "app/src/main/assets/cve-2026-43499-standalone",
            "app/src/main/assets/ksud-asteroids",
            "app/src/main/jniLibs/arm64-v8a/libcve43499root.so",
        },
        ONEPLUS_ROOT: {
            "app/src/main/assets/cve-2026-43499-standalone",
            "app/src/main/assets/ksud-oneplus-pad3",
            "app/src/main/jniLibs/arm64-v8a/libcve43499root.so",
        },
    }
    for device_root, rels in expected_assets.items():
        for rel in rels:
            path = ROOT / device_root / rel
            if not path.is_file() or path.stat().st_size == 0:
                errors.append(f"missing or empty pinned app artifact: {device_root / rel}")

    # Neither Android app should have a reason to use the network.
    for device_root in EXPECTED_DEVICE_ROOTS:
        manifest = ROOT / device_root / "app/src/main/AndroidManifest.xml"
        if "android.permission.INTERNET" in manifest.read_text(encoding="utf-8"):
            errors.append(f"unexpected Internet permission: {manifest.relative_to(ROOT)}")

    nothing_script = (ROOT / NOTHING_ROOT / "tools/build-asteroids-fixed.sh").read_text(encoding="utf-8")
    oneplus_script = (ROOT / ONEPLUS_ROOT / "tools/build-oneplus-pad3.sh").read_text(encoding="utf-8")
    if '$RMD/patches/$KSU_VERSION/devices/asteroids/' not in nothing_script:
        errors.append("Nothing build script does not use the shared Asteroids patch series")
    for label, script in (("Nothing", nothing_script), ("OnePlus", oneplus_script)):
        if 'KERNELSU_SOURCE="$REPOSITORY_ROOT/src/kernelsu/KernelSU"' not in script:
            errors.append(f"{label} build script does not use the shared KernelSU submodule")
        if 'RMD="$REPOSITORY_ROOT/src/kernelsu/Root-My-Device-KSU"' not in script:
            errors.append(f"{label} build script does not use the shared patch submodule")


def audit_gradle_wrappers(errors: list[str]) -> None:
    for device_root in sorted(EXPECTED_DEVICE_ROOTS):
        directory = ROOT / device_root / "gradle/wrapper"
        properties = directory / "gradle-wrapper.properties"
        wrapper_jar = directory / "gradle-wrapper.jar"
        try:
            values = {}
            for line in properties.read_text(encoding="utf-8").splitlines():
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    values[key] = value
        except OSError as error:
            errors.append(f"unable to read {properties.relative_to(ROOT)}: {error}")
            continue
        if values.get("distributionUrl") != GRADLE_DISTRIBUTION_URL:
            errors.append(
                f"{properties.relative_to(ROOT)} distributionUrl is not the pinned Gradle 9.5.1 URL"
            )
        if values.get("distributionSha256Sum") != GRADLE_DISTRIBUTION_SHA256:
            errors.append(
                f"{properties.relative_to(ROOT)} distributionSha256Sum mismatch"
            )
        if not wrapper_jar.is_file() or sha256(wrapper_jar) != GRADLE_WRAPPER_JAR_SHA256:
            errors.append(f"{wrapper_jar.relative_to(ROOT)} official checksum mismatch")


def audit_source_provenance(errors: list[str], gitlinks: dict[Path, str]) -> None:
    path = ROOT / "SOURCE_PROVENANCE.json"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except Exception as error:
        errors.append(f"unable to parse SOURCE_PROVENANCE.json: {error}")
        return

    actual = {
        item.get("path"): item.get("sourceCommit")
        for item in document.get("deviceSources", [])
        if isinstance(item, dict)
    }
    if actual != EXPECTED_SOURCE_PROVENANCE:
        errors.append(
            f"source provenance mismatch: {actual} != {EXPECTED_SOURCE_PROVENANCE}"
        )

    submodules = {
        item.get("path"): item.get("commit")
        for item in document.get("sharedSubmodules", [])
        if isinstance(item, dict)
    }
    expected = {
        "src/kernelsu/KernelSU": PINNED_SUBMODULES[Path("src/kernelsu/KernelSU")],
        "src/kernelsu/Root-My-Device-KSU": "tracked-gitlink",
    }
    if submodules != expected:
        errors.append(f"provenance submodule mismatch: {submodules} != {expected}")
    rmd_gitlink = gitlinks.get(Path("src/kernelsu/Root-My-Device-KSU"))
    if not rmd_gitlink:
        errors.append("Root-My-Device-KSU gitlink is missing")


def audit_markdown_links(errors: list[str]) -> None:
    link_pattern = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
    for path in ROOT.rglob("*.md"):
        if ".git" in path.parts or "src/kernelsu" in path.as_posix():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for target in link_pattern.findall(text):
            target = target.strip()
            if not target or target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            local = target.split("#", 1)[0]
            if not local:
                continue
            destination = (path.parent / local).resolve()
            try:
                destination.relative_to(ROOT.resolve())
            except ValueError:
                errors.append(f"Markdown link escapes repository: {path.relative_to(ROOT)} -> {target}")
                continue
            if not destination.exists():
                errors.append(f"broken Markdown link: {path.relative_to(ROOT)} -> {target}")


def main() -> int:
    errors: list[str] = []

    if not (ROOT / ".git").exists():
        errors.append(".git is missing")
    if not (ROOT / ".gitmodules").is_file():
        errors.append(".gitmodules is missing")

    origin = run("git", "config", "--get", "remote.origin.url")
    actual_origin = normalize_git_url(origin.stdout) if not origin.returncode else ""
    if origin.returncode or actual_origin != EXPECTED_ORIGIN:
        errors.append(
            f"top-level origin mismatch: {origin.stdout.strip() or 'missing'} != {EXPECTED_ORIGIN}"
        )

    branch = run("git", "symbolic-ref", "--quiet", "--short", "HEAD")
    if branch.returncode or branch.stdout.strip() != "main":
        errors.append(
            f"top-level branch mismatch: {branch.stdout.strip() or 'detached'} != main"
        )

    try:
        entries = tracked_entries()
    except Exception as error:
        errors.append(f"unable to enumerate tracked files: {error}")
        entries = []

    gitlinks: dict[Path, str] = {}
    entry_modes = {relative: mode for mode, _oid, relative in entries}
    for executable in sorted(EXPECTED_EXECUTABLES):
        actual_mode = entry_modes.get(executable)
        if actual_mode != "100755":
            errors.append(
                f"executable mode mismatch: {executable} is "
                f"{actual_mode or 'untracked'}, expected 100755"
            )

    for mode, oid, relative in entries:
        if mode == "160000":
            gitlinks[relative] = oid
            continue
        path = ROOT / relative
        if mode == "120000":
            try:
                target = os.readlink(path)
            except OSError as error:
                errors.append(f"unable to read symlink {relative}: {error}")
                continue
            if os.path.isabs(target) or ".." in Path(target).parts:
                errors.append(f"unsafe tracked symlink {relative} -> {target}")
            continue
        if not path.is_file():
            errors.append(f"tracked file is missing: {relative}")
            continue
        if relative.suffix.lower() in CREDENTIAL_SUFFIXES:
            errors.append(f"credential-like file is tracked: {relative}")
        if relative.suffix.lower() in {".apk", ".aab", ".apks"}:
            errors.append(f"release package is tracked instead of published separately: {relative}")
        data = path.read_bytes()
        scan_forbidden(data, str(relative), errors)
        if (
            relative.suffix.lower() not in CRLF_ALLOWED_SUFFIXES
            and is_probably_text(relative, data)
            and b"\r\n" in data
        ):
            errors.append(f"{relative} contains CRLF line endings")

    if set(gitlinks) != REQUIRED_SUBMODULE_PATHS:
        errors.append(
            "submodule gitlink set mismatch: "
            + repr({str(path): oid for path, oid in gitlinks.items()})
        )
    for path, expected in PINNED_SUBMODULES.items():
        actual = gitlinks.get(path)
        if actual != expected:
            errors.append(f"{path} gitlink mismatch: {actual or 'missing'} != {expected}")

    gitmodules_text = (ROOT / ".gitmodules").read_text(encoding="utf-8") if (ROOT / ".gitmodules").is_file() else ""
    for path, url in EXPECTED_SUBMODULE_URLS.items():
        if f"path = {path.as_posix()}" not in gitmodules_text:
            errors.append(f".gitmodules is missing path {path}")
        if f"url = {url}" not in gitmodules_text:
            errors.append(f".gitmodules is missing URL {url}")

    audit_profiles(errors)
    audit_device_isolation(errors)
    audit_gradle_wrappers(errors)
    audit_source_provenance(errors, gitlinks)
    audit_markdown_links(errors)
    audit_git_repository(ROOT, "top-level repository", errors, scan_history=False)

    for path in sorted(REQUIRED_SUBMODULE_PATHS):
        expected_head = PINNED_SUBMODULES.get(path) or gitlinks.get(path, "")
        audit_submodule_worktree(path, expected_head, errors)

    for args, label in (
        (("git", "diff", "--check"), "git diff --check"),
        (("git", "diff", "--cached", "--check"), "git diff --cached --check"),
    ):
        status = run(*args)
        if status.returncode:
            errors.append(status.stdout.strip() or status.stderr.strip() or f"{label} failed")

    if errors:
        print("Root My Device public-tree audit failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print(
        "Root My Device public-tree audit passed "
        f"({len(entries)} tracked entries, 2 exact device projects)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
