# Security policy

## Supported scope

Only the two exact device profiles documented in `README.md` and the matching
per-device README files are supported. A matching product name alone is not a
supported configuration. Every OTA, regional build, fingerprint, kernel, ABI,
or page-size change must be treated as a new target and must not reuse offsets
speculatively.

## Reporting a vulnerability

Use a private GitHub Security Advisory for vulnerabilities in either Android
application, the build pipeline, artifact verification, signer handling,
submodule/patch selection, or completion-receipt logic. Do not open a public
issue containing an unpatched vulnerability, signing material, unique device
identifiers, or a working crash/panic reproducer.

A useful report includes:

- the affected repository commit and device directory;
- the exact firmware and kernel profile;
- expected and observed behavior;
- a minimal reproducer without personal data;
- sanitized app logs and relevant artifact SHA-256 values;
- whether the issue can corrupt state, cross a trust boundary, select the wrong
  device artifact, or accept a false success result.

## Sensitive data

Never attach keystores, passwords, private keys, account identifiers, device
serial numbers, IP/Wi-Fi details, full package inventories, or unsanitized
`adb bugreport` archives. Review build and diagnostic logs before publication.

## Operational safety

Do not test on devices you do not own or lack explicit permission to use. Save
work before testing because an exploit miss can reboot or panic the kernel.
Never bypass an exact-profile check or delete a dirty-state marker to force a
same-boot retry. Never substitute artifacts from the sibling device project.
