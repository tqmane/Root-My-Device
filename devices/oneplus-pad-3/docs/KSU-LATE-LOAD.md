# OnePlus Pad 3 KernelSU late-load contract

The OnePlus Pad 3 build treats the Root app, Manager, module, `ksud`, helper,
and payload as one authenticated set.

## Signing identity

`tools/build-oneplus-pad3.sh` requires an explicit `RMOP_*` signing identity.
The certificate DER size and SHA-256 are compiled into `kernelsu.ko`; the final
Root My Device KSU Manager and Root app are signed with the same key and checked
with `apksigner`. A generic/public Manager cannot authenticate to this module.

No keystore path, alias, or password is committed. Passwords are passed to the
relevant signing subprocesses through environment-backed interfaces rather
than repository properties or a built-in local file.

## Binary identity chain

The build establishes and verifies:

```text
payload embeds SHA-256(helper)
helper  embeds SHA-256(ksud)
ksud    embeds the exact kernelsu.ko
Manager embeds the exact ksud
app     pins payload/helper/ksud size + SHA-256
stamp   records payload/helper/ksud/module identities
```

Gradle refuses to assemble an app if this chain or the committed pins are stale.
The runtime verifies files again before execution and after Shizuku staging.

## Runtime sequence

1. Acquire the temporary-root helper route and verify explicit receipts.
2. Stage the exact `ksud` and request `late-load --modules`.
3. Verify the live KernelSU control plane.
4. Run late-load-compatible module setup and mount stages.
5. Recreate the zygote/system_server boundary once.
6. Verify the replacement framework and target-specific Vector/service state.
7. Restore SELinux enforcing and publish the root-private completion receipt.
8. Verify the receipt against current boot ID, app run nonce, and exact `ksud`
   identity before reporting completion.

“KernelSU active” by itself is not sufficient evidence that module stages or
framework recreation completed.

## Retry policy

The initial Pad 3 module path is tied to the same authenticated late-load. If a
run enters a mutating kernel primitive or leaves the current-boot dirty marker,
reboot before retrying. Do not force-stop the native child or remove the marker
to make another attempt in the same boot.
