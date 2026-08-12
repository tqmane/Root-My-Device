# Root My Device

[English](README.md) · [セキュリティ方針](SECURITY.md)

Root My Deviceは、次の2台向けの **exact-build専用** temporary root → KernelSU
late-load projectを1つにまとめた公開用monorepoです。

- [Nothing Phone (3a)](devices/nothing-phone-3a/README.ja.md)
- [OnePlus Pad 3](devices/oneplus-pad-3/README.ja.md)

Android app、native payload、target profile、同梱artifact、build outputは端末ごとに
分離しています。生成されるのは **端末別の2種類のAPK一式**であり、万能APKでは
ありません。共有するのはpin済みKernelSU source 2件だけです。

Exploit payload、bootstrap helper、`ksud`は対応するappへ同梱されます。実行時に
exploit codeをdownloadせず、analyticsもなく、Internet permissionも要求しません。
Temporary rootとlive-loadされたKernelSU moduleは通常の再起動後に消えます。

> [!WARNING]
> Kernel vulnerabilityを利用するため、race failureや想定外の状態で端末が再起動・panic
> する可能性があります。作業中のデータを保存し、自分が所有する端末または明示的に
> 許可された端末だけで使用してください。Exact-profile guardやsame-boot dirty-state
> guardを回避しないでください。

## 対応するexact target

次のOTA・regional variant・firmware・kernel・ABI・page size以外の動作は保証しません。

| Project | 必須identity | Kernel / exploit core | 確認状態 |
| --- | --- | --- | --- |
| Nothing Phone (3a) | `MODEL=A059`、`DEVICE=Asteroids`、build `B4.1-260618-1048`、Android 16 / SDK 36、security patch `2026-06-01` | `6.1.157-android14-11-g82d681c9b06b-ab14634535`、`android14-6.1`、`core61`、arm64、4096-byte page | Maintainer実機でtemporary root、KernelSU 32525 late-load、Manager認証、module stageまで確認済みです。 |
| OnePlus Pad 3 | `MODEL=OPD2415`、`DEVICE=OP6190L1`、`PRODUCT=OPD2415IN`、build `OPD2415_16.0.9.400(EX01)`、Android 16 / SDK 36、security patch `2026-07-01` | `6.6.118-android15-8-g2e6b9c3812c5-ab15114928-4k`、`android15-6.6`、`core66`、arm64、4096-byte page | Maintainer実機でtemporary root、KernelSU 32525 late-load、signer-matched Manager grant、module/Vector stageまで確認済みです。 |

各appは端末別READMEに記載した完全なprofileを照合してからRootを有効化します。
Model名やproduct名だけの一致では対応扱いになりません。

## 行う処理と行わない処理

端末別projectは、exact device/build/fingerprint/security patch/kernel/ABI/page size、
同梱artifactのsize・SHA-256を検証し、Shizuku経由でatomicに配置します。その後、target
固有のCVE-2026-43499 route、KernelSU 32525 late-load、paired `ksud`、current-bootの
module-stage完了を検証します。Kernel stateを変更し得る段階以降は危険なsame-boot再試行を
拒否します。

Bootloader unlock、data wipe、AVB無効化、boot image patch、partition flash、永続root、
別firmware用offsetの推測は行いません。

## Source provenance

端末別fileの統合元は次の通りです。

- `root-my-nothing` source HEAD:
  `58df2d94cb907b589eef5f26f21f214a249c85b8`
- `root-my-oneplus` source HEAD:
  `ff7294631fce27e5cf0a345346dc16bb04d2412b`

統合repoの`main`は新しいintegration commitです。そのため、repo rootの
`git rev-parse HEAD`が上記2つと異なるのは正常です。Machine-readableな対応は
[`SOURCE_PROVENANCE.json`](SOURCE_PROVENANCE.json)に記録しています。

## Repository構成

```text
devices/
  nothing-phone-3a/          A059向け独立Android/native project
  oneplus-pad-3/             OPD2415向け独立Android/native project
src/kernelsu/
  KernelSU/                  共有pin済みupstream submodule
  Root-My-Device-KSU/        共有pin済みpatch submodule
tools/
  build-all.sh               署名対応の2端末一括release build
  audit-public-tree.py       公開・構成・Git監査
SOURCE_PROVENANCE.json       source/submodule commitの対応表
```

端末directory内にnested `.git`や重複したKernelSU submoduleはありません。

## 共有submodule pin

- KernelSU: `b0bc817b4e966aa6aa830834eaf6ef765d821d40`（`32525`）
- Root-My-Device-KSU: `bf5bfa9ba0e7430611cca4b55ab12885df2d4eaa`

このpatch commitには、KernelSU 32525 common 6件、Asteroids 3件、OnePlus Pad 3
13件が入っています。各device buildはcommon seriesの後に自分のdevice seriesだけを
適用します。同じcommit内の他version・他端末patchは選択しません。

```bash
git submodule update --init --recursive
```

## Build環境

Linux x86-64上で、Git、Docker、JDK 21、API 37を含むAndroid SDK、`zipalign -P 16`
対応build-tools、Android NDK `29.0.14206865`、`aarch64-linux-android` targetを追加した
Rust/Cargo、Python 3、GNU Make、各端末README記載のELF/binutils toolsを用意します。
OnePlus chainは`pyelftools`、`bpftool`、`nm`、host C compilerも必要です。

```bash
export ANDROID_HOME="$HOME/Android/Sdk"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/29.0.14206865"
```

### 2端末を1回でrelease build

従来の端末別署名環境変数を設定したまま、次で一括buildできます。

```bash
./tools/build-all.sh --release
# 同じ処理
make release
```

Nothing Manager、Nothing Root app、OnePlusの両APKを1つの署名identityで作る場合は、
次の共通shortcutも使えます。

```bash
export ROOT_MY_DEVICE_KEYSTORE=/absolute/path/release-signing.p12
export ROOT_MY_DEVICE_KEY_ALIAS=key0
export ROOT_MY_DEVICE_STORE_PASSWORD='...'
export ROOT_MY_DEVICE_KEY_PASSWORD='...'

./tools/build-all.sh --release
```

共通変数は未設定の端末別変数だけを補います。明示した`RMD_MANAGER_*`、`RMN_*`、
`RMOP_*`が優先されます。Wrapperはcredentialを扱う前にshell xtraceを無効化し、passwordを
表示しません。[`signing.env.example`](signing.env.example)と
`./tools/build-all.sh --help`も参照してください。

```bash
./tools/build-all.sh --release --plan
./tools/build-all.sh --release --nothing-only
./tools/build-all.sh --release --oneplus-only --verify-oneplus-device
./tools/build-all.sh --release --oneplus-only --oneplus-serial SERIAL
```

### 端末別に直接build

```bash
cd devices/nothing-phone-3a
./tools/build-asteroids-fixed.sh --release
```

```bash
cd devices/oneplus-pad-3
./tools/build-oneplus-pad3.sh --release
```

署名変数、output set、read-only verificationの詳細は各端末READMEを確認してください。

## Artifactを混ぜない

Nothing Phone (3a)とOnePlus Pad 3のpayload、helper、`ksud`、Manager APK、Root APKは
相互交換できません。同じ端末buildで生成された一式をまとめて保持してください。

## Local検査

```bash
python3 tools/audit-public-tree.py
make artifacts
make contracts
```

`make check`は両Android appのunit testとdebug APK assembleも行うため、完全なSDK/JDKと
Gradle artifactが必要です。

## Privacyと公開

Keystore、password、private key、local absolute path、device serial、account identifier、
未sanitiseのlog・bugreportを公開しないでください。

## License / Credits

Main projectは[Apache License 2.0](LICENSE)です。Submodule、研究コード、dependency、
patch、生成binaryはKernelSU関連のGPLを含む各licenseに従います。
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)と各submodule内licenseを確認してください。
