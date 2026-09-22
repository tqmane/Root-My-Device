# Root My Nothing quick start

This guide is only for the three exact Nothing Phone (3a) builds, which share the same kernel release:

- `MODEL=A059`
- `DEVICE=Asteroids`
- `BUILD=B4.1-260618-1048` (`2026-06-01`), `B4.1-260810-1153` (`2026-08-01`), or `C5.0-260915-2123` (`2026-09-01`)
- kernel `6.1.157-android14-11-g82d681c9b06b-ab14634535`
- Android 16 / SDK 36 (`260618`, `260810`) or Android 17 / SDK 37 (`260915`), `arm64-v8a`, 4096-byte pages

Do not run it on any other OTA or regional build: display, fingerprint, and
security patch must form one supported set.

## 1. Build one matched set

From the monorepo root:

```bash
git submodule update --init --recursive
export ANDROID_HOME="$HOME/Android/Sdk"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/29.0.14206865"
cd devices/nothing-phone-3a
./tools/build-asteroids-fixed.sh
```

The final lines print paths for the Root app, signer-matched Root My Device KSU
Manager, exact `ksud`, and `kernelsu.ko`. Keep them together. Do not substitute
a generic Manager or any OnePlus artifact.

## 2. Install both APKs

Install the Root app and Manager printed by the same build. The Manager
certificate must match the identity compiled into `kernelsu.ko`.

## 3. Start Shizuku

Start Shizuku through USB or wireless debugging and grant Root My Nothing
permission. The service must run as Android's `shell` user.

## 4. Verify and run

Open Root My Nothing and require **Compatible**. Check model, build, kernel, and
page size, then tap **Root**.

An exploit miss may reboot the phone. Module setup may restart Android
framework and close the app. Reopen it after Android returns and verify both
KernelSU and module-stage completion.

## Failure handling

- A clean pre-primitive failure may be retried only as indicated by the app.
- After a current dirty marker or entered kernel primitive, reboot before retry.
- Never delete the marker to force a same-boot run.
- After reboot, start Shizuku again; temporary root and the module are gone.

Export and sanitize logs before rebooting when reporting a problem.
