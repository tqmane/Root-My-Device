# Root My Nothing — Nothing Phone (3a)

[日本語](README.ja.md) · [Quick start](QUICKSTART.en.md) · [Repository overview](../../README.md)

This directory is the independent Nothing Phone (3a) application and native
build chain inside the Root My Device monorepo. It implements an **exact-build**
temporary-root → KernelSU late-load flow for one A059/Asteroids firmware.

The app runs the bundled native payload through Shizuku's shell service,
validates every supported device field before enabling Root, stages a matching
KernelSU userspace daemon, and runs the late module stages used by the tested
Zygisk/Vector-compatible setup.

The exploit payload, bootstrap helper, and `ksud` are packaged in the APK. The
app does not download exploit code, use analytics, or request Internet access.
Root is temporary and disappears after a normal reboot.

> [!WARNING]
> This project exercises a kernel vulnerability. A failed race or an incorrect
> environment can reboot or panic the phone. Save active work first. Use it only
> on a device you own or are explicitly authorized to test.

## Supported target

This device project supports **one exact target only**:

| Field | Required value |
| --- | --- |
| Device | Nothing Phone (3a) |
| Model | `A059` |
| Device codename | `Asteroids` |
| Build display | `B4.1-260618-1048` |
| Fingerprint | `Nothing/AsteroidsJPN/Asteroids:16/BQ2A.250721.001-BP2A.250605.031.A3/2606181048:user/release-keys` |
| Android / SDK | Android 16 / SDK 36 |
| Security patch | `2026-06-01` |
| Kernel | `6.1.157-android14-11-g82d681c9b06b-ab14634535` |
| KMI / exploit core | `android14-6.1` / `core61` |
| ABI / page size | `arm64-v8a` / 4096 bytes |
| Status | Maintainer device-verified: temporary root, KernelSU 32525 late-load, Manager authentication, and module-stage flow work on this exact build. |

The application compares model, device, build display, full fingerprint, SDK,
security patch, kernel release, ABI, and page size. A Nothing OS OTA, regional
variant, or another Phone (3a) build is **not** implicitly supported.

## Runtime flow

1. Verify the exact device profile and Shizuku shell identity.
2. Verify the embedded payload/helper/`ksud` by byte size and SHA-256.
3. Stage files through Shizuku with private temporary files and atomic rename.
4. Run the CVE-2026-43499 path and require explicit temporary-root receipts.
5. Load the exact `android14-6.1` KernelSU module carried by the paired `ksud`.
6. Verify KernelSU is live and bind the result to the current boot.
7. Run the explicit module stages and verify their completion marker.

Once a potentially mutating kernel primitive has been entered, the native and
application guards avoid an unsafe same-boot retry. Reboot before retrying a
dirty failure. Do not delete the dirty marker to bypass the guard.

## Build from source

### Requirements

Use the common host requirements in the [monorepo README](../../README.md), then
initialize the shared submodules from the repository root:

```bash
git submodule update --init --recursive
export ANDROID_HOME="$HOME/Android/Sdk"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/29.0.14206865"
cd devices/nothing-phone-3a
```

Build a debug Root app and signer-matched Root My Device KSU Manager:

```bash
./tools/build-asteroids-fixed.sh
```

The script creates or reuses a local Manager key under the ignored
`build/asteroids-fixed/` directory, compiles that certificate identity into
`kernelsu.ko`, embeds the matching `ksud` in the Manager, rebuilds the native
payload/helper set, synchronizes APK pins, and assembles the Root app.

To use an existing Manager key, set all four variables:

```bash
export RMD_MANAGER_KEYSTORE=/absolute/path/manager-signing.p12
export RMD_MANAGER_KEY_ALIAS=manager
export RMD_MANAGER_STORE_PASSWORD='...'
export RMD_MANAGER_KEY_PASSWORD='...'
./tools/build-asteroids-fixed.sh
```

A release Root app additionally requires:

```bash
export RMN_KEYSTORE=/absolute/path/root-my-nothing.p12
export RMN_KEY_ALIAS=root-my-nothing
export RMN_STORE_PASSWORD='...'
export RMN_KEY_PASSWORD='...'
./tools/build-asteroids-fixed.sh --release
```

No keystore path, alias, or password is built into the repository. Signing
files, local SDK paths, generated outputs, and diagnostic logs are ignored.

> [!IMPORTANT]
> Install the **Manager APK produced by the same native build**. KernelSU
> authenticates the Manager certificate compiled into the module, and the
> paired Manager must carry the exact `ksud`. Do not substitute a generic
> public Manager.

## Shared KernelSU patch source

This project consumes the six common KernelSU 32525 patches and the three
`asteroids` patches from the shared monorepo submodule pinned to
`bf5bfa9ba0e7430611cca4b55ab12885df2d4eaa`. The build script verifies that
exact submodule HEAD and applies only those nine patches to the pinned KernelSU
checkout.

## Artifact integrity

The application carries these native files as one tested set:

```text
cve-2026-43499-standalone
libcve43499root.so
ksud-asteroids
```

`tools/sync-asteroids-app-artifacts.py` copies them atomically, updates
`ArtifactStore.kt`, and writes `.asteroids-artifacts-synced`. Gradle and runtime
both verify the committed size/SHA-256 identities. Never replace one file with
an artifact from another build or from the OnePlus project.

## Directory layout

```text
app/                         Android application and pinned native artifacts
src/payloads/                CVE-2026-43499 core61 and bootstrap sources
src/targets/asteroids/       exact A059 profile only
tools/                       exact build and artifact synchronization
diagnostics/asteroids/       optional device-side diagnostic helpers
docs/DEVICE.md               exact profile and runtime contract
```

The sibling `devices/oneplus-pad-3/` tree is a separate project and is not part
of this app's target selection.

## Install and run

See [QUICKSTART.en.md](QUICKSTART.en.md). Install both APKs from the same build,
start Shizuku as Android shell, confirm every displayed profile field, and tap
Root. Module setup may restart Android framework and close the app; reopen it
after the framework returns and verify module-stage completion.

## Security, reports, and licensing

Use the shared [security policy](../../SECURITY.md) and
[contribution rules](../../CONTRIBUTING.md). Remove account names, serial
numbers, IP addresses, and unrelated package data from public logs.

The main project is under [Apache License 2.0](../../LICENSE). KernelSU-related
and copied code retain their own upstream licenses. See
[THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md).
