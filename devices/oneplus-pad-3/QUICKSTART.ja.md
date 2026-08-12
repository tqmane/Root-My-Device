# Root My OnePlus Pad 3 クイックスタート

対象は次のexact targetのみです。

- Model/device/product: `OPD2415` / `OP6190L1` / `OPD2415IN`
- OxygenOS: `OPD2415_16.0.9.400(EX01)`
- Kernel: `6.6.118-android15-8-g2e6b9c3812c5-ab15114928-4k`
- Android 16 / SDK 36 / `arm64-v8a` / 4096-byte page

OTA後や別地域buildでは実行しないでください。

## 1. Signer-matched一式をbuild

Monorepo rootから実行します。

```bash
git submodule update --init --recursive
python3 -m pip install --user pyelftools
export ANDROID_HOME="$HOME/Android/Sdk"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/29.0.14206865"
cd devices/oneplus-pad-3

export RMOP_KEYSTORE=/absolute/path/oneplus-pad3-signing.p12
export RMOP_KEY_ALIAS=oneplus-pad3
export RMOP_STORE_PASSWORD='...'
export RMOP_KEY_PASSWORD='...'

./tools/build-oneplus-pad3.sh --release
```

最後にRoot app、signer-matched Manager、`ksud`、`kernelsu.ko`、build manifestのpathが
表示されます。同じ一式として保持し、Nothing Phone (3a) artifactや汎用Managerへ
置き換えないでください。

Read-onlyのtarget確認:

```bash
./tools/build-oneplus-pad3.sh --release --verify-device
```

## 2. 2つのAPKをinstall

同じrunが生成した`app-release.apk`と`RootMyDeviceKSU_32525_OnePlusPad3.apk`をinstallします。

## 3. Shizukuを起動

USB debuggingまたはwireless debuggingからShizukuを起動し、Root appへpermissionを付与
します。Androidの`shell` userとして動作する必要があります。

## 4. 確認して実行

Root My OnePlus Pad 3を開き、**Compatible**であること、model/product/build/kernel/pageの
全表示が一致することを確認して**Root**を押します。

Exploit missで再起動する可能性があります。Module setupはAndroid framework boundaryを
再生成するためappが閉じる場合があります。復帰後に開き直し、`KernelSU active`だけでなく
verified module-stage completionを確認します。

## 失敗時

Kernel primitive enteredまたはcurrent dirty markerが表示された後は再起動してください。
Markerを消してsame-boot実行を強制しないでください。再起動後はtemporary root/moduleが
消えるためShizukuも起動し直します。

問題報告時は再起動前にlogをexportし、個人情報を削除してください。
