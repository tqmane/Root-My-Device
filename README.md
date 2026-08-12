# Root My Device

[日本語](README.ja.md) · [Security policy](SECURITY.md) · [Publishing notes](PUBLISHING.md)

Root My Device is a public monorepo for two **exact-build**, temporary-root →
KernelSU late-load projects:

- [Nothing Phone (3a)](devices/nothing-phone-3a/README.md)
- [OnePlus Pad 3](devices/oneplus-pad-3/README.md)

The Android applications, native payloads, target profiles, artifacts, and
build outputs remain isolated by device. The repository produces **two
independent APK sets, not one universal APK**. Only the two pinned KernelSU
source repositories are shared.

The exploit payload, bootstrap helper, and `ksud` are bundled with the matching
application. Neither app downloads exploit code, uses analytics, nor requests
Internet access. Temporary root and the live-loaded KernelSU module disappear
after a normal reboot.

> [!WARNING]
> These projects exercise a kernel vulnerability. A failed race or unexpected
> state may reboot or panic the device. Save active work first and use the
> software only on hardware you own or are explicitly authorized to test.
> Never bypass an exact-profile or same-boot dirty-state guard.

## Supported exact targets

No other OTA, regional variant, firmware, kernel, ABI, or page-size combination
is implied to work.

| Project | Required identity | Kernel / exploit core | Verification status |
| --- | --- | --- | --- |
| Nothing Phone (3a) | `MODEL=A059`, `DEVICE=Asteroids`, build `B4.1-260618-1048`, Android 16 / SDK 36, security patch `2026-06-01` | `6.1.157-android14-11-g82d681c9b06b-ab14634535`, `android14-6.1`, `core61`, arm64, 4096-byte pages | Maintainer device-verified for temporary root, KernelSU 32525 late-load, Manager authentication, and module stages on the exact profile. |
| OnePlus Pad 3 | `MODEL=OPD2415`, `DEVICE=OP6190L1`, `PRODUCT=OPD2415IN`, build `OPD2415_16.0.9.400(EX01)`, Android 16 / SDK 36, security patch `2026-07-01` | `6.6.118-android15-8-g2e6b9c3812c5-ab15114928-4k`, `android15-6.6`, `core66`, arm64, 4096-byte pages | Maintainer device-verified for temporary root, KernelSU 32525 late-load, signer-matched Manager grant, and module/Vector stages on the exact profile. |

Each application validates the complete profile documented in its device README
before enabling Root. A model or product name alone is not sufficient.

## Runtime scope

The device projects:

1. validate the exact device, build, fingerprint, security patch, kernel, ABI,
   and page size;
2. verify bundled native artifacts by byte size and SHA-256;
3. stage artifacts through Shizuku using private temporary files and atomic
   replacement;
4. run the target-specific CVE-2026-43499 path and require explicit receipts;
5. late-load the matching KernelSU 32525 module and start its paired `ksud`;
6. verify current-boot KernelSU and module-stage completion before reporting
   success; and
7. refuse unsafe same-boot retries after a potentially mutating kernel stage.

They do **not** unlock the bootloader, wipe data, disable AVB, patch a boot
image, flash a partition, install persistent root, or guess offsets for another
firmware.

## Source provenance

The device files were integrated from these source repositories:

- `root-my-nothing` source HEAD:
  `58df2d94cb907b589eef5f26f21f214a249c85b8`
- `root-my-oneplus` source HEAD:
  `ff7294631fce27e5cf0a345346dc16bb04d2412b`

The combined repository has its own new integration commit. It is therefore
correct for `git rev-parse HEAD` at the monorepo root to differ from both source
HEADs. Machine-readable provenance is in
[`SOURCE_PROVENANCE.json`](SOURCE_PROVENANCE.json).

## Repository layout

```text
devices/
  nothing-phone-3a/          independent A059 Android/native project
  oneplus-pad-3/             independent OPD2415 Android/native project
src/kernelsu/
  KernelSU/                  shared pinned upstream submodule
  Root-My-Device-KSU/        shared pinned patch submodule
tools/
  build-all.sh               signer-aware combined release build
  audit-public-tree.py       publication/layout/Git audit
SOURCE_PROVENANCE.json       exact source and submodule commits
```

There are no nested device repositories or duplicated device-level KernelSU
submodules in the current tree.

## Pinned shared submodules

- KernelSU: `b0bc817b4e966aa6aa830834eaf6ef765d821d40` (`32525`)
- Root-My-Device-KSU: `bf5bfa9ba0e7430611cca4b55ab12885df2d4eaa`

The patch commit contains the six KernelSU 32525 common patches, three
Asteroids patches, and thirteen OnePlus Pad 3 patches used here. Each device
build applies only its own device series after the common series. Other patch
families present in that exact submodule commit are not selected by either
build.

Initialize both shared worktrees from the repository root:

```bash
git submodule update --init --recursive
```

## Build requirements

Use a Linux x86-64 host with Git, Docker, JDK 21, Android SDK API 37,
build-tools supporting `zipalign -P 16`, Android NDK `29.0.14206865`,
Rust/Cargo with the `aarch64-linux-android` target, Python 3, GNU Make, and the
ELF/binutils dependencies listed in each device README. The OnePlus chain also
requires `pyelftools`, `bpftool`, `nm`, and a host C compiler.

```bash
export ANDROID_HOME="$HOME/Android/Sdk"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/29.0.14206865"
```

### Build both release sets in one command

The existing per-device signing variables remain supported. Set them and run:

```bash
./tools/build-all.sh --release
# equivalent Make target:
make release
```

For one signing identity across the Nothing Manager, Nothing Root app, and both
OnePlus APKs, use the optional shorthand:

```bash
export ROOT_MY_DEVICE_KEYSTORE=/absolute/path/release-signing.p12
export ROOT_MY_DEVICE_KEY_ALIAS=key0
export ROOT_MY_DEVICE_STORE_PASSWORD='...'
export ROOT_MY_DEVICE_KEY_PASSWORD='...'

./tools/build-all.sh --release
```

The wrapper fills only missing per-device variables, so explicit
`RMD_MANAGER_*`, `RMN_*`, or `RMOP_*` values take precedence. It disables shell
xtrace before handling credentials and never prints passwords. See
[`signing.env.example`](signing.env.example) and `./tools/build-all.sh --help`.

Optional examples:

```bash
./tools/build-all.sh --release --plan
./tools/build-all.sh --release --nothing-only
./tools/build-all.sh --release --oneplus-only --verify-oneplus-device
./tools/build-all.sh --release --oneplus-only --oneplus-serial SERIAL
```

### Build a device directly

```bash
cd devices/nothing-phone-3a
./tools/build-asteroids-fixed.sh --release
```

```bash
cd devices/oneplus-pad-3
./tools/build-oneplus-pad3.sh --release
```

Consult each device README for its exact signing variables, output set, and
optional verification behavior.

## Do not mix artifacts

Nothing Phone (3a) and OnePlus Pad 3 payloads, helpers, `ksud` binaries, Manager
APKs, and Root APKs are not interchangeable. Keep every output set together and
install only the Manager generated by the same device build.

## Local verification

```bash
python3 tools/audit-public-tree.py
make artifacts
make contracts
```

`make check` additionally runs both Android unit-test suites and debug APK
assemblies, so it requires a complete Android/JDK environment and Gradle
artifacts.

## Privacy and publishing

Do not publish keystores, passwords, private keys, local absolute paths, device
serial numbers, account identifiers, unsanitized logs, or bugreports. Read
[PUBLISHING.md](PUBLISHING.md) before pushing. Retaining the exact
`bf5bfa9…` submodule commit also retains that commit's original Git metadata;
rewriting it would necessarily change the hash.

## Credits and licensing

The main project is distributed under the [Apache License 2.0](LICENSE).
Submodules, copied research code, dependencies, patches, and generated binaries
retain their own licenses, including GPL terms for KernelSU-related code. See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and the license files inside
each submodule.
