# Contributing

This repository contains two deliberately isolated exact-device projects.
Changes should make a supported target safer, more reproducible, or easier to
audit without quietly broadening its compatibility claim or mixing artifacts
between devices.

## Before opening a change

1. Identify the affected directory: `devices/nothing-phone-3a` or
   `devices/oneplus-pad-3`.
2. Keep each existing `TARGET` and `CORE` unchanged unless the change is a
   separately reviewed new-target port.
3. Do not copy physical addresses, structure offsets, tuning values, payloads,
   helpers, or `ksud` binaries from the sibling project or a neighboring device.
4. Do not weaken model/product/fingerprint/kernel/ABI/page-size checks,
   dirty-state guards, signer checks, or completion-receipt validation.
5. Rebuild and synchronize every paired artifact as one set. Never edit only a
   size/SHA-256 constant to silence a guard.
6. Do not commit keystores, passwords, local absolute paths, raw device logs,
   generated build directories, APKs, or personal identifiers.
7. Keep shared submodule pins explicit. Both device patch series come from
   `src/kernelsu/Root-My-Device-KSU` pinned to
   `bf5bfa9ba0e7430611cca4b55ab12885df2d4eaa`; do not copy or edit them in the
   main tree.

## Local checks

```bash
python3 tools/audit-public-tree.py
make syntax
make contracts
make apps
```

`make apps` requires JDK 21 and Android SDK API 37. Native-chain changes also
require the toolchains documented in the device README and a fresh run of the
corresponding exact build script.

## Pull request notes

State the device directory and exact build tested, whether testing was
source-only or performed on real hardware, and the SHA-256 identities of any
rebuilt artifacts. Remove serial numbers and personal data from logs. A clean
static check is not a claim that a new firmware or kernel is device-verified.
Historical evidence labels must remain honest.
