# Third-party notices

This repository combines device-specific integration with pinned upstream
projects and research-derived code. Main-project source is distributed under
`LICENSE` (Apache License 2.0). Each dependency and copied component remains
subject to its own license and notices.

| Component | Location or use | Upstream | License source |
| --- | --- | --- | --- |
| KernelSU | `src/kernelsu/KernelSU` submodule | `tiann/KernelSU` | `src/kernelsu/KernelSU/LICENSE` and component-specific files |
| Root My Device KSU patches / Manager integration | `src/kernelsu/Root-My-Device-KSU` submodule | `tqmane/Root-My-Device-KSU` | submodule `LICENSE`, `LICENSE.kernel-GPL-2.0`, and file headers |
| Shizuku API/provider | both Android applications | `RikkaApps/Shizuku-API` | upstream license and dependency metadata |
| AndroidX / Jetpack Compose / Kotlin coroutines | Android application dependencies | Android Open Source Project / JetBrains | upstream artifact license metadata |
| CVE-2026-43499 payload lineage | both `devices/*/src/payloads` trees | Root-My-Galaxy-Payloads and CyberMeowfia research listed in `README.md` | retained upstream notices and file headers where present |

The Root-My-Device-KSU submodule is pinned to
`bf5bfa9ba0e7430611cca4b55ab12885df2d4eaa`. The Nothing build selects the six
KernelSU 32525 common patches and three Asteroids patches. The OnePlus build
selects the same common patches and thirteen OnePlus Pad 3 patches. No patch is
copied into the main repository.

Distributing a source archive, APK, Manager APK, native helper, `ksud`, or
kernel module does not replace the obligation to comply with every included
license. Review this file and all upstream license files whenever a dependency,
submodule pin, copied source file, or binary is updated.

## Credits

This project builds on and adapts work from the following upstream projects and research:

- **[Root-My-Galaxy-Payloads](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads)** by **BuSung-dev**  
  Reference implementation and payload lineage for device-specific CVE-2026-43499 exploitation, bootstrap helpers, firmware profiles, and KernelSU late-load integration.

- **[CyberMeowfia — CVE-2026-43499 exploit](https://github.com/NebuSec/CyberMeowfia/tree/main/IonStack/CVE-2026-43499/exploit)** by **NebuSec**  
  Original/public research and exploit implementation used as a technical basis for the CVE-2026-43499 exploit path.

- **[Root-My-Device-Payloads](https://github.com/WitAqua-tools/Root-My-Device-Payloads)** by **WitAqua-tools**  
  Device-oriented payload, profile, helper, and KernelSU artifact work used as a reference and upstream source for this project.

- **[Root-My-Device-KSU](https://github.com/WitAqua-tools/Root-My-Device-KSU)** by **WitAqua-tools**  
  KernelSU patches and integration work used by the device-specific build pipelines in this repository.

Many thanks to the authors and contributors of these projects for publishing their work and research.

The acknowledgements above do not replace or modify the license terms of any upstream project. Each copied, modified, linked, or redistributed component remains subject to its original license and notices.
