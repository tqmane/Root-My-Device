# OneLineage → Nothing Phone (3a): stage-0 compatibility research

> [!WARNING]
> **Not an installable or bootable port.** This directory only contains read-only diagnostics. Never run the unmodified Samsung takeover scripts on Asteroids.

This isolated integration investigates [WeWaffles/OneLineage](https://github.com/WeWaffles/OneLineage) with GhostLock → temporary KernelSU root from [Root My Device](../../README.md). It does not modify the exploit, unlock the bootloader, flash partitions or attempt any userspace takeover.

## Architecture and blockers

OneLineage currently runs a LineageOS 23.2 Android 16 GSI via a loop-mounted system image, a private mount namespace, pivot_root, guest SurfaceFlinger/zygote/system_server and handover from a Samsung One UI 8.5 host. It assumes Samsung imsd, Samsung launcher app data, Samsung-specific patched framework/PermissionController binaries, host APEX inventory, global SELinux/eBPF alterations, and particular daemon topology. These assumptions need a Nothing-specific implementation and real device tests.

Root My Device uses **current-boot-only** GhostLock → late-load KernelSU. After reboot, exploit root is gone. Never bypass its exact-profile/dirty-state guards.

## Supported root-profile identities

| Firmware | Host | Root-My-Device status | OneLineage status |
| --- | --- | --- | --- |
| B4.1-260618-1048 | Android 16 | Device verified | Read-only probe only |
| B4.1-260810-1153 | Android 16 | Supported | Read-only probe only |
| C5.0-260915-2123 | Android 17 | Allowlisted, root not fully verified | Rejected by analyzer |

The exact host kernel is `6.1.157-android14-11-g82d681c9b06b-ab14634535` and the target is `A059` / `Asteroids`, arm64, 4096-byte pages. Other profiles are blocked; passing this check never asserts that OneLineage boots.

## Use on a currently rooted device (non-destructive)

Grant ADB shell root permission in the signer-matched KernelSU Manager, **without rerunning GhostLock**. In this folder, run:

```sh
adb push probe.sh /data/local/tmp/onelineage-asteroids-probe.sh
adb shell 'su -c "/system/bin/sh /data/local/tmp/onelineage-asteroids-probe.sh"' > report.txt
python3 analyze.py report.txt
python3 -m unittest discover -p 'test_*.py'
```

The probe reads identity, privileges and mount/binder/APEX/service capabilities; `unshare -m` starts a disposable namespace with no-op `:`, and `losetup -f` only queries a free loop device. It **does not** change SELinux mode, mount partitions, kill daemons, edit kernel nodes, modify eBPF maps, change USB configuration, or execute a GSI. Inspect logs before sharing.

## Next implementation milestones

1. Capture the host Nothing OS Android 16 service and APEX inventory, and audit GSI binary patch compatibility. Do not reuse Samsung `clean_apex_info_list.xml` or patched jars blindly.
2. Implement device-specific guest vendor/HAL, binder and radio/IMS handling and verify SurfaceFlinger, media codec and Wi-Fi service ownership. Never assume Samsung `imsd` exists.
3. Move guest data and storage mappings behind dedicated mount namespaces, remove world-writable shared host paths, and avoid system-wide eBPF edits/hardcoded loop-device minor numbers.
4. Implement a safe pre-takeover gate and a stock reboot recovery path before allowing any host zygote/surfaceflinger stop, with working ADB logs and backups.
5. Dry-run every step and verify a controlled real boot. Check stock return, graphics, input, calls, camera, audio, Wi-Fi, storage, apps, sensors and SELinux behavior.

**Keep this independent of the security exploit implementation.** Do not merge unfinished takeover code into Root My Device. OneLineage did not declare a repository license on 2026-10-22; clarify redistribution permission before bundling upstream source or its patched binary assets.
