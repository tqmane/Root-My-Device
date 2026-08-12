# OnePlus Pad 3 safe build and bring-up procedure

This procedure is limited to the exact OPD2415 profile committed in this
repository. It separates read-only verification, source build, and on-device
execution so that a build step cannot accidentally flash or wipe a device.

## 1. Read-only device guard

With exactly one intended device connected:

```bash
python3 tools/verify-target.py --require-locked
```

For multiple devices, pass `--serial`. The command reads model/device/product,
full build identity, kernel, ABI/page size, and verified-boot properties. It
does not reboot, unlock, flash, or write to the tablet.

## 2. Optional boot-image reproduction

Use a stock `boot.img` obtained through a lawful source for the exact build:

```bash
python3 tools/extract-boot.py /absolute/path/to/boot.img \
  --output-dir generated/oneplus-pad-3 \
  --force
```

Generated analysis files are ignored by Git. Do not commit proprietary firmware
images or local absolute paths. The committed profile/evidence files are the
reviewable inputs; a filename alone is never treated as proof of identity.

## 3. Static contract verification

The release script runs the source/profile negative fixtures automatically.
They can also be run independently:

```bash
python3 tools/verify-profile.py --mode4-contract-self-test
python3 tools/verify-a3-source-contract.py
python3 tools/verify-profile.py --reclaim-contract-self-test
```

A full `verify-profile.py` run additionally needs the exact locally extracted
kernel, vmlinux, BTF, kallsyms, and Module.symvers files.

## 4. Signer-matched release build

```bash
export ANDROID_HOME="$HOME/Android/Sdk"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/29.0.14206865"
export RMOP_KEYSTORE=/absolute/path/oneplus-pad3-signing.p12
export RMOP_KEY_ALIAS=oneplus-pad3
export RMOP_STORE_PASSWORD='...'
export RMOP_KEY_PASSWORD='...'
./tools/build-oneplus-pad3.sh --release --verify-device
```

The script rejects missing signing variables and does not contain a private
keystore path, alias, or password. Restrict keystore/password-file permissions
to the owner. The final app and Manager are signature-verified, and the same
certificate identity is compiled into the module.

## 5. Installation and execution

Install only the two APKs emitted by the same build. Start Shizuku, confirm the
exact compatibility card, and run Root from the app. No manual helper command
or direct native execution is part of the supported end-user path.

The initial module late-load can restart zygote/system_server and close the app.
Wait for Android to return, reopen the app, and require its trusted completion
receipt. Do not infer success from a single process or log line.

## 6. Failure boundary

A clean pre-primitive failure may be retriable. Once the dirty marker is
committed, do not terminate the native child, delete the marker, or start a
second exploit in the same boot. Reboot and start Shizuku again.

## 7. Log handling

Export app logs before rebooting. Redact serial numbers, account identifiers,
IP addresses, unrelated package names, and private paths before publication.
Device probes under `diagnostics/oneplus-pad3/` are optional developer tools.
