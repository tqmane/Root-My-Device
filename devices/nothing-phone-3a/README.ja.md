# Root My Nothing — Nothing Phone (3a)

[English](README.md) · [クイックスタート](QUICKSTART.ja.md) · [Repository概要](../../README.ja.md)

このdirectoryは、Root My Device monorepo内のNothing Phone (3a)向け独立Android app・
native build chainです。A059/Asteroidsの1つのfirmwareだけを対象に、**exact-build専用**
temporary root → KernelSU late-loadを行います。

Shizukuのshell serviceからAPK内蔵native payloadを実行し、対応端末情報をすべて照合して
から、対応するKernelSU module/`ksud`とmodule stageを起動します。

Exploit payload、bootstrap helper、`ksud`はAPKに同梱されます。実行時にexploit codeを
downloadせず、analyticsもなく、Internet permissionも要求しません。Rootは一時的で、
通常の再起動後に消えます。

> [!WARNING]
> Kernel vulnerabilityを利用するため、raceの失敗や環境差により端末が再起動・panicする
> 可能性があります。作業中のデータを保存し、自分が所有する端末または明示的に許可された
> 端末だけで使用してください。

## 対応target

このdevice projectが対応するのは次の **1 buildのみ**です。

| 項目 | 必須値 |
| --- | --- |
| 端末 | Nothing Phone (3a) |
| Model | `A059` |
| Device codename | `Asteroids` |
| Build display | `B4.1-260618-1048` |
| Fingerprint | `Nothing/AsteroidsJPN/Asteroids:16/BQ2A.250721.001-BP2A.250605.031.A3/2606181048:user/release-keys` |
| Android / SDK | Android 16 / SDK 36 |
| Security patch | `2026-06-01` |
| Kernel | `6.1.157-android14-11-g82d681c9b06b-ab14634535` |
| KMI / exploit core | `android14-6.1` / `core61` |
| ABI / page size | `arm64-v8a` / 4096 bytes |
| 状態 | Maintainer実機でtemporary root、KernelSU 32525 late-load、Manager認証、module stageまで確認済みです。 |

Appはmodel、device、build display、完全なfingerprint、SDK、security patch、kernel release、
ABI、page sizeを照合します。Nothing OSのOTA後・別地域・別Phone (3a) buildは自動的には
対応しません。

## Runtime処理

1. Exact device profileとShizuku shell identityを確認します。
2. APK内のpayload/helper/`ksud`をsizeとSHA-256で検証します。
3. Shizukuからprivate temporary fileとatomic renameを使って配置します。
4. CVE-2026-43499 routeを実行し、temporary-rootの明示的なreceiptを確認します。
5. 対応する`android14-6.1` KernelSU moduleをlate-loadします。
6. KernelSU live stateを確認し、current bootへresultを結び付けます。
7. 明示的なmodule stageを実行し、completion markerを確認します。

Kernel stateを変更し得る段階以降で失敗した場合は、危険なsame-boot再実行を避けます。
Dirty markerを削除して強制再試行せず、端末を再起動してください。

## Source build

[Monorepo README](../../README.ja.md)の共通host要件を用意し、repository rootでsubmoduleを
初期化します。

```bash
git submodule update --init --recursive
export ANDROID_HOME="$HOME/Android/Sdk"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/29.0.14206865"
cd devices/nothing-phone-3a
```

Debug Root appとsigner-matched Root My Device KSU Managerをbuildします。

```bash
./tools/build-asteroids-fixed.sh
```

Scriptは無視対象の`build/asteroids-fixed/`以下にlocal Manager keyを生成または再利用し、
certificate identityを`kernelsu.ko`へ組み込み、matching `ksud`をManagerへ入れ、native
payload/helper一式とAPK pinを同期してRoot appをassembleします。

既存Manager keyを使う場合:

```bash
export RMD_MANAGER_KEYSTORE=/absolute/path/manager-signing.p12
export RMD_MANAGER_KEY_ALIAS=manager
export RMD_MANAGER_STORE_PASSWORD='...'
export RMD_MANAGER_KEY_PASSWORD='...'
./tools/build-asteroids-fixed.sh
```

Release Root appも作る場合:

```bash
export RMN_KEYSTORE=/absolute/path/root-my-nothing.p12
export RMN_KEY_ALIAS=root-my-nothing
export RMN_STORE_PASSWORD='...'
export RMN_KEY_PASSWORD='...'
./tools/build-asteroids-fixed.sh --release
```

Repository内にkeystore path、alias、passwordの既定値はありません。Signing file、local SDK
path、生成物、診断logはGit対象外です。

> [!IMPORTANT]
> **同じnative buildが生成したManager APK**をinstallしてください。KernelSUはmoduleへ
> 組み込んだManager certificateを認証し、paired Managerもexact `ksud`を保持する必要が
> あります。汎用public Managerへ置き換えないでください。

## 共有KernelSU patch

KernelSU 32525 common 6件と`asteroids` 3件を、
`bf5bfa9ba0e7430611cca4b55ab12885df2d4eaa`へpinした共有monorepo submoduleから
使用します。Build scriptはsubmodule HEADの完全一致を検査し、その9件だけをpin済み
KernelSU checkoutへ適用します。

## Artifact一体性

次の3fileは1組です。

```text
cve-2026-43499-standalone
libcve43499root.so
ksud-asteroids
```

`tools/sync-asteroids-app-artifacts.py`がatomic copy、`ArtifactStore.kt`のpin更新、
`.asteroids-artifacts-synced`生成を行います。Gradle/runtimeの両方でsize/SHA-256を確認
します。別buildやOnePlus projectのartifactと混ぜないでください。

## Directory構成

```text
app/                         Android appとpinned native artifacts
src/payloads/                CVE-2026-43499 core61 / bootstrap source
src/targets/asteroids/       A059 exact profileのみ
tools/                       exact build / artifact sync
diagnostics/asteroids/       任意の実機diagnostic helper
docs/DEVICE.md               exact profile / runtime contract
```

Siblingの`devices/oneplus-pad-3/`は別projectであり、このappのtarget selectionには入りません。

## 実行・報告・license

[QUICKSTART.ja.md](QUICKSTART.ja.md)を参照してください。同じbuildの2APKをinstallし、
Shizukuをshellとして起動してprofileを確認後Rootを実行します。Module setupでframeworkが
再起動してappが閉じた場合は、復帰後に開き直してcompletionを確認してください。

共有の[SECURITY.md](../../SECURITY.md)と[CONTRIBUTING.md](../../CONTRIBUTING.md)に従い、
公開logからaccount name、serial、IP address、無関係なpackage情報を削除してください。
Main projectは[Apache License 2.0](../../LICENSE)です。詳細は
[THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md)を確認してください。
