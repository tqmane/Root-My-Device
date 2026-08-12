# Root My Nothing クイックスタート

対象は次のexact Nothing Phone (3a)のみです。

- `MODEL=A059`
- `DEVICE=Asteroids`
- `BUILD=B4.1-260618-1048`
- Kernel `6.1.157-android14-11-g82d681c9b06b-ab14634535`
- Android 16 / `arm64-v8a` / 4096-byte page

OTA後や別地域buildでは実行しないでください。

## 1. 対応する一式をbuild

Monorepo rootから実行します。

```bash
git submodule update --init --recursive
export ANDROID_HOME="$HOME/Android/Sdk"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/29.0.14206865"
cd devices/nothing-phone-3a
./tools/build-asteroids-fixed.sh
```

最後にRoot app、signer-matched Root My Device KSU Manager、exact `ksud`、`kernelsu.ko`の
pathが表示されます。同じ一式として保持し、汎用ManagerやOnePlus artifactへ置き換えないで
ください。

## 2. 2つのAPKをinstall

同じbuildが出力したRoot appとManagerを入れます。Manager certificateは`kernelsu.ko`へ
組み込んだidentityと一致する必要があります。

## 3. Shizukuを起動

USB debuggingまたはwireless debuggingからShizukuを起動し、Root My Nothingへpermissionを
付与します。ServiceはAndroidの`shell` userとして動作する必要があります。

## 4. 確認して実行

Root My Nothingを開き、**Compatible**であること、model/build/kernel/page sizeが一致する
ことを確認して**Root**を押します。

Exploit missで再起動する可能性があります。Module setupでAndroid frameworkが再起動して
appが閉じた場合は、復帰後に開き直してKernelSUとmodule-stage completionを確認します。

## 失敗時

- Kernel primitive前のclean failureはapp表示に従う場合だけ再試行できます。
- Current dirty markerまたはprimitive entered後は再起動してください。
- Markerを消してsame-boot実行を強制しないでください。
- 再起動後はtemporary root/moduleが消えるためShizukuも起動し直します。

問題報告時は再起動前にlogをexportし、個人情報を削除してください。
