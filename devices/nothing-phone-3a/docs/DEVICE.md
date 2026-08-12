# Nothing Phone (3a) A059 / Asteroids exact profile

This document records the target contract used by Root My Nothing. It is not a
claim of compatibility with every Nothing Phone (3a).

## Identity guard

| Property | Exact value |
| --- | --- |
| `ro.product.model` | `A059` |
| `ro.product.device` | `Asteroids` |
| `ro.build.display.id` | `B4.1-260618-1048` |
| `ro.build.fingerprint` | `Nothing/AsteroidsJPN/Asteroids:16/BQ2A.250721.001-BP2A.250605.031.A3/2606181048:user/release-keys` |
| Android SDK | `36` |
| Security patch | `2026-06-01` |
| `uname -r` | `6.1.157-android14-11-g82d681c9b06b-ab14634535` |
| primary ABI | `arm64-v8a` |
| page size | `4096` |

The app requires every identity row above before it stages or executes the payload.
A mismatch fails closed. The corresponding source profile is under:

```text
src/targets/asteroids/jp/6.1.157-android14-11-g82d681c9b06b-ab14634535/
```

`target-core61.h` contains the exact symbol/structure/constants consumed by the
`android14-6.1` exploit core. `p0_fingerprint.h` and the target root glue bind
the physical/KASLR route to this firmware. The Makefile accepts no other target
or core in this public device-specific repository.

## Runtime contract

The app does not treat process exit alone as success. It requires the native
root receipts, verifies the exact staged files, confirms KernelSU is live, and
stores a current-boot receipt. Module completion is accepted only when the
current boot marker and receipt agree.

A run that may have entered a mutating kernel primitive is intentionally not
retried in the same boot. Rebooting clears temporary root and resets the safe
run boundary.

## KernelSU pairing

The exact module is built from the pinned KernelSU revision declared by the
build script and the `devices/asteroids` patch set. KernelSU authenticates its
Manager using the certificate identity compiled at module-build time. Always
install the Manager emitted by the same build and carrying the same `ksud`.

## Diagnostics

The files under `diagnostics/asteroids/` are developer-oriented helpers for
collecting late-load and reclaim information. They are not required for normal
app use and may produce device-specific logs; review them before publishing.
