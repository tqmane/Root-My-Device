# OnePlus Pad 3 exact target profile

## Identity

| Property | Exact value |
| --- | --- |
| Marketing name | OnePlus Pad 3 |
| Model | `OPD2415` |
| Device | `OP6190L1` |
| Product | `OPD2415IN` |
| Build display | `OPD2415_16.0.9.400(EX01)` |
| Fingerprint | `OnePlus/OPD2415IN/OP6190L1:16/AP3A.240617.008/V.R4T3.17bf73d_cf42a1_c9913b:user/release-keys` |
| Security patch | `2026-07-01` |
| Android / SDK | Android 16 / 36 |
| Kernel | `6.6.118-android15-8-g2e6b9c3812c5-ab15114928-4k` |
| KMI | `android15-6.6` |
| ABI / page size | `arm64-v8a` / 4096 |

The app requires every field above, including SDK and security patch. A
different fingerprint or full kernel release requires a separate reviewed profile.

## Committed profile files

```text
src/targets/oneplus-pad3/ex/6.6.118-android15-8-g2e6b9c3812c5-ab15114928-4k/
  target-core66.h
  offsets.h
  struct-offsets.h
  pselect-profile.h
  kernel.config
  profile.json
  reclaim-evidence.json
  kernelsnitch-quality-evidence.json
  kernelsu.json
```

The target is bound to `core66`. The public Makefile and release build reject
another target/core combination. The unrelated feature-off compile header is
kept explicitly under `tools/fixtures/`, not represented as a supported device.

## Physical and runtime gates

The committed physical profile uses:

```text
PHYS_OFFSET       = 0x80000000
KERNEL_PHYS_LOAD  = 0xa8000000
```

The value is derived from the exact XBL Kernel region and constrained by region
bounds/alignment. Before later root/SELinux mutations, the release route also
requires live-image qword validation and exact target-specific invariants. It
does not perform blind candidate writes or enable the unvalidated direct-root
fallback.

The KASLR route uses the target's random-UUID/nfulnl layout and requires exact
restoration/readback. The legacy boot-ID slide route is not present in the Pad
3 release payload.

## Evidence labels

Several JSON fields retain `pending-...-rerun` or `provisional-...` wording from
the point at which that specific static/diagnostic evidence was captured. They
are provenance labels, not a broad runtime support flag. The shipped exact
build is maintainer-confirmed working; the historical evidence is intentionally
not relabelled as an observation it did not itself record.

## Reproduction

Use `tools/extract-boot.py` with a lawful exact stock image and keep outputs
under ignored `generated/`. `tools/verify-profile.py` binds committed hashes,
BTF/structure fields, static disassembly, source contracts, and negative
fixtures. See [BRINGUP.md](BRINGUP.md).
