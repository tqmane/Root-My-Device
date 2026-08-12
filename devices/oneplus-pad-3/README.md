# Root My OnePlus Pad 3

[日本語](README.ja.md) · [Quick start](QUICKSTART.en.md) · [Repository overview](../../README.md)

This directory is the independent OnePlus Pad 3 application and native build
chain inside the Root My Device monorepo. It implements an **exact-build**
temporary-root → KernelSU late-load flow for one OPD2415 firmware.

The app runs the bundled CVE-2026-43499 chain through Shizuku, verifies the full
target identity, validates a pinned payload → helper → `ksud` chain, late-loads
the exact KernelSU userspace/module set, and validates the module/zygote-stage
completion result.

Payload, bootstrap helper, and `ksud` are packaged in the APK. The app does not
download exploit code, use analytics, or request Internet access. Temporary root
and the live-loaded module disappear after a normal reboot.

> [!WARNING]
> This project exercises a kernel vulnerability. A failed race or unexpected
> tablet state may reboot or panic the device. Save active work first and use it
> only on a device you own or are explicitly authorized to test.

## Supported target

This device project supports **one exact target only**:

| Field | Required value |
| --- | --- |
| Device | OnePlus Pad 3 |
| Model / device / product | `OPD2415` / `OP6190L1` / `OPD2415IN` |
| OxygenOS build | `OPD2415_16.0.9.400(EX01)` |
| Fingerprint | `OnePlus/OPD2415IN/OP6190L1:16/AP3A.240617.008/V.R4T3.17bf73d_cf42a1_c9913b:user/release-keys` |
| Android / SDK | Android 16 / SDK 36 |
| Security patch | `2026-07-01` |
| Kernel | `6.6.118-android15-8-g2e6b9c3812c5-ab15114928-4k` |
| KMI / exploit core | `android15-6.6` / `core66` |
| ABI / page size | `arm64-v8a` / 4096 bytes |
| Status | Maintainer device-verified: temporary root, KernelSU 32525 late-load, signer-matched Manager grant, and module/Vector stages work on this exact build. |

Model, device, product, build display, full fingerprint, SDK, security patch,
kernel release, ABI, and page size must all match. An OTA or another regional
build is not implicitly supported.

Historical evidence labels such as `pending-exact-device-rerun` describe the
provenance of individual static/bring-up captures. They do not override the
maintainer verification status above and must not be rewritten to claim a run
that the capture did not record.

## Runtime flow

1. Verify the exact tablet profile and optional locked/green boot state.
2. Verify payload/helper/`ksud` size and SHA-256 identities.
3. Validate the payload → helper → `ksud` build-pin chain.
4. Stage files through Shizuku with private temporary files and atomic rename.
5. Run the target-specific CVE-2026-43499 route and require a root receipt.
6. Late-load the exact `android15-6.6` KernelSU module carried by `ksud`.
7. Recreate the module/zygote/system-server boundary and verify a completion
   receipt bound to current boot, run nonce, and exact `ksud` identity.

Once the kernel primitive dirty marker is current, the app will not run the
exploit again in the same boot. Reboot instead of deleting the marker.

## Build from source

Use the common host requirements in the [monorepo README](../../README.md), then
initialize the shared submodules from the repository root:

```bash
git submodule update --init --recursive
python3 -m pip install --user pyelftools
export ANDROID_HOME="$HOME/Android/Sdk"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/29.0.14206865"
cd devices/oneplus-pad-3
```

The release build requires one explicit signing identity for both APKs:

```bash
export RMOP_KEYSTORE=/absolute/path/oneplus-pad3-signing.p12
export RMOP_KEY_ALIAS=oneplus-pad3
export RMOP_STORE_PASSWORD='...'
export RMOP_KEY_PASSWORD='...'
./tools/build-oneplus-pad3.sh --release
```

The same certificate signs the Root app and Root My Device KSU Manager and is
compiled into `kernelsu.ko`. Passwords may be read from an explicitly selected
`RMOP_PASSWORD_FILE`; no default path, alias, password, or private workstation
setting is built into the repository.

Optional read-only connected-device verification:

```bash
./tools/build-oneplus-pad3.sh --release --verify-device
# Multiple devices: add --serial DEVICE_SERIAL
```

The verification mode reads properties and boot state only. The build script
does not unlock, wipe, flash, install, or reboot a connected device.

## Shared KernelSU patch source

This project consumes the six common patches and thirteen `oneplus-pad3`
patches from `../../src/kernelsu/Root-My-Device-KSU`, pinned to
`bf5bfa9ba0e7430611cca4b55ab12885df2d4eaa`. The same submodule also contains
the Asteroids series, but the OnePlus build does not select or apply it.

## One coherent output set

Do not mix files from separate builds:

```text
cve-2026-43499-standalone
cve-2026-43499-root
kernelsu.ko
ksud-oneplus-pad3
RootMyDeviceKSU_32525_OnePlusPad3.apk
app-release.apk
build-manifest.txt
```

The helper embeds the exact `ksud` SHA-256, the payload embeds the exact helper
SHA-256, and the app/stamp pin all identities. Gradle rejects a mixed set.
Nothing Phone (3a) artifacts are also incompatible.

## Directory layout

```text
app/                         Android app and pinned native artifacts
src/payloads/                CVE-2026-43499 core66 / bootstrap source
src/targets/oneplus-pad3/    exact OPD2415 EX01 profile and evidence
src/kernelsu/tools/          target-specific module audit helper
tools/                       extraction, verification, build, sync tooling
tools/fixtures/              explicit non-target compile fixture
diagnostics/oneplus-pad3/    optional read-only/developer probes
docs/                        target and late-load contracts
generated/                   ignored local extraction output
```

The sibling `devices/nothing-phone-3a/` tree is a separate project and is not
part of this app's target selection.

## Install and run

See [QUICKSTART.en.md](QUICKSTART.en.md). Install the Root app and Manager from
the same build, start Shizuku as Android shell, confirm every target field, and
tap Root. Module setup intentionally recreates the Android framework boundary
and may close the app; reopen it and require verified module-stage completion,
not only “KernelSU active.”

## Security, reports, and licensing

Use the shared [security policy](../../SECURITY.md) and
[contribution rules](../../CONTRIBUTING.md). Remove account names, serial
numbers, IP addresses, and unrelated package data from public logs.

The main project is under [Apache License 2.0](../../LICENSE). KernelSU-related
and copied code retain their own upstream licenses. See
[THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md).
