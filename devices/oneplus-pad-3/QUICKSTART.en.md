# Root My OnePlus Pad 3 quick start

This guide supports one exact target only:

- model/device/product: `OPD2415` / `OP6190L1` / `OPD2415IN`
- OxygenOS: `OPD2415_16.0.9.400(EX01)`
- kernel: `6.6.118-android15-8-g2e6b9c3812c5-ab15114928-4k`
- Android 16 / SDK 36 / `arm64-v8a` / 4096-byte pages

Do not run it after an OTA or on another regional build.

## 1. Build one signer-matched set

From the monorepo root:

```bash
git submodule update --init --recursive
python3 -m pip install --user pyelftools
export ANDROID_HOME="$HOME/Android/Sdk"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/29.0.14206865"
cd devices/oneplus-pad-3

export RMOP_KEYSTORE=/absolute/path/oneplus-pad3-signing.p12
export RMOP_KEY_ALIAS=oneplus-pad3
export RMOP_STORE_PASSWORD='...'
export RMOP_KEY_PASSWORD='...'

./tools/build-oneplus-pad3.sh --release
```

The script prints the Root app, signer-matched Manager, `ksud`, `kernelsu.ko`,
and build manifest. Keep the complete set together. Do not substitute Nothing
Phone (3a) artifacts or a generic Manager.

Optional read-only target verification:

```bash
./tools/build-oneplus-pad3.sh --release --verify-device
```

## 2. Install both APKs

Install `app-release.apk` and the `RootMyDeviceKSU_32601_OnePlusPad3.apk`
produced by the same run.

## 3. Start Shizuku

Start Shizuku through USB or wireless debugging and grant the Root app
permission. It must run as Android's `shell` user.

## 4. Verify and run

Open Root My OnePlus Pad 3. Require **Compatible** and verify every displayed
model/product/build/kernel/page field before tapping **Root**.

An exploit miss may reboot the tablet. Module setup intentionally recreates the
Android framework boundary and may close the app. Reopen it and require verified
module-stage completion, not only “KernelSU active.”

## Failure handling

After the app reports an entered kernel primitive or current dirty marker,
reboot before retrying. Never delete the marker to force a same-boot run. Start
Shizuku again after reboot because temporary root and the module are gone.

Export and sanitize logs before rebooting when reporting a problem.
