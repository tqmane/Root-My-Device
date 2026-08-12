# Root My OnePlus Pad 3

[English](README.md) · [クイックスタート](QUICKSTART.ja.md) · [Repository概要](../../README.ja.md)

このdirectoryは、Root My Device monorepo内のOnePlus Pad 3向け独立Android app・native
build chainです。OPD2415の1つのfirmwareだけを対象に、**exact-build専用** temporary
root → KernelSU late-loadを行います。

Shizuku経由でAPK内蔵CVE-2026-43499 chainを実行し、完全なtarget identity、payload →
helper → `ksud` pin chain、exact KernelSU userspace/module、module/zygote-stage completionを
検証します。

Payload、bootstrap helper、`ksud`はAPKに同梱されます。実行時にexploit codeをdownload
せず、analyticsもなく、Internet permissionも要求しません。Temporary rootとlive-loaded
moduleは通常の再起動後に消えます。

> [!WARNING]
> Kernel vulnerabilityを利用するため、race failureや想定外のtablet状態によって再起動・
> panicする可能性があります。作業中のデータを保存し、自分が所有する端末または明示的に
> 許可された端末だけで使用してください。

## 対応target

このdevice projectが対応するのは次の **1 buildのみ**です。

| 項目 | 必須値 |
| --- | --- |
| 端末 | OnePlus Pad 3 |
| Model / device / product | `OPD2415` / `OP6190L1` / `OPD2415IN` |
| OxygenOS build | `OPD2415_16.0.9.400(EX01)` |
| Fingerprint | `OnePlus/OPD2415IN/OP6190L1:16/AP3A.240617.008/V.R4T3.17bf73d_cf42a1_c9913b:user/release-keys` |
| Android / SDK | Android 16 / SDK 36 |
| Security patch | `2026-07-01` |
| Kernel | `6.6.118-android15-8-g2e6b9c3812c5-ab15114928-4k` |
| KMI / exploit core | `android15-6.6` / `core66` |
| ABI / page size | `arm64-v8a` / 4096 bytes |
| 状態 | Maintainer実機でtemporary root、KernelSU 32525 late-load、signer-matched Manager grant、module/Vector stageまで確認済みです。 |

Model、device、product、build display、完全なfingerprint、SDK、security patch、kernel
release、ABI、page sizeのすべてが一致する必要があります。OTA後や別地域buildは自動的には
対応しません。

`pending-exact-device-rerun`などの過去evidence labelは、個別captureを生成した時点の
provenanceです。上記のmaintainer確認状態を上書きするものではなく、実際に記録していない
runへlabelを書き換えないでください。

## Runtime処理

1. Exact tablet profileと、任意でlocked/green boot stateを確認します。
2. Payload/helper/`ksud`のsizeとSHA-256を検証します。
3. Payload → helper → `ksud`のbuild pin chainを検証します。
4. Shizukuからprivate temporary fileとatomic renameを使って配置します。
5. Target固有のCVE-2026-43499 routeを実行し、root receiptを要求します。
6. `ksud`内のexact `android15-6.6` KernelSU moduleをlate-loadします。
7. Module/zygote/system-server boundaryを再生成し、current boot、run nonce、exact `ksud`
   identityへ結び付いたcompletion receiptを検証します。

Kernel primitive dirty markerがcurrentになった後は、同じbootでexploitを再実行しません。
Markerを削除せず再起動してください。

## Source build

[Monorepo README](../../README.ja.md)の共通host要件を用意し、repository rootでsubmoduleを
初期化します。

```bash
git submodule update --init --recursive
python3 -m pip install --user pyelftools
export ANDROID_HOME="$HOME/Android/Sdk"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/29.0.14206865"
cd devices/oneplus-pad-3
```

Release buildは両APKへ使う1つのsigning identityを明示的に要求します。

```bash
export RMOP_KEYSTORE=/absolute/path/oneplus-pad3-signing.p12
export RMOP_KEY_ALIAS=oneplus-pad3
export RMOP_STORE_PASSWORD='...'
export RMOP_KEY_PASSWORD='...'
./tools/build-oneplus-pad3.sh --release
```

同じcertificateでRoot appとRoot My Device KSU Managerを署名し、そのidentityを
`kernelsu.ko`へ組み込みます。Passwordは明示した`RMOP_PASSWORD_FILE`から読むことも
できますが、repository内に既定path、alias、password、private workstation設定はありません。

接続端末をread-onlyで確認する場合:

```bash
./tools/build-oneplus-pad3.sh --release --verify-device
# 複数台接続時は --serial DEVICE_SERIAL を追加
```

Verification modeはpropertyとboot stateを読むだけです。Build scriptはconnected deviceの
unlock、wipe、flash、install、rebootを行いません。

## 共有KernelSU patch

Common 6件と`oneplus-pad3` 13件を、
`bf5bfa9ba0e7430611cca4b55ab12885df2d4eaa`へpinした
`../../src/kernelsu/Root-My-Device-KSU`から使用します。同じsubmodule内のAsteroids seriesは
このbuildでは選択・適用しません。

## 1つのoutput setを混ぜない

```text
cve-2026-43499-standalone
cve-2026-43499-root
kernelsu.ko
ksud-oneplus-pad3
RootMyDeviceKSU_32525_OnePlusPad3.apk
app-release.apk
build-manifest.txt
```

Helperはexact `ksud` SHA-256、payloadはexact helper SHA-256を内蔵し、app/stampも全identityを
pinします。別buildやNothing Phone (3a)のartifactと混ぜるとGradleが拒否します。

## Directory構成

```text
app/                         Android appとpinned native artifacts
src/payloads/                CVE-2026-43499 core66 / bootstrap source
src/targets/oneplus-pad3/    exact OPD2415 EX01 profile / evidence
src/kernelsu/tools/          target固有module audit helper
tools/                       extraction / verification / build / sync
tools/fixtures/              明示的なnon-target compile fixture
diagnostics/oneplus-pad3/    任意のread-only/developer probe
docs/                        target / late-load contract
generated/                   Git対象外local extraction output
```

Siblingの`devices/nothing-phone-3a/`は別projectであり、このappのtarget selectionには入りません。

## 実行・報告・license

[QUICKSTART.ja.md](QUICKSTART.ja.md)を参照してください。同じbuildのRoot appとManagerを
installし、Shizukuをshellとして起動して全target fieldを確認後Rootを実行します。Module
setupはAndroid framework boundaryを再生成するためappが閉じる場合があります。復帰後に
開き直し、`KernelSU active`だけでなくverified module-stage completionを確認してください。

共有の[SECURITY.md](../../SECURITY.md)と[CONTRIBUTING.md](../../CONTRIBUTING.md)に従い、
公開logからaccount name、serial、IP address、無関係なpackage情報を削除してください。
Main projectは[Apache License 2.0](../../LICENSE)です。詳細は
[THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md)を確認してください。
