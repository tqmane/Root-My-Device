#!/usr/bin/env bash
# Rebuild the Nothing Phone (3a) Asteroids native chain, a signer-matched
# Root My Device KSU Manager, and the Root My Nothing APK from source.
# This script never touches a phone. It only builds local artifacts.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
if [ -n "${ROOT_MY_DEVICE_REPOSITORY_ROOT:-}" ]; then
  REPOSITORY_ROOT=$(cd "$ROOT_MY_DEVICE_REPOSITORY_ROOT" && pwd)
elif [ -d "$ROOT/../../src/kernelsu" ] && [ -d "$ROOT/../../devices" ]; then
  REPOSITORY_ROOT=$(cd "$ROOT/../.." && pwd)
else
  REPOSITORY_ROOT="$ROOT"
fi
TARGET='asteroids/jp/6.1.157-android14-11-g82d681c9b06b-ab14634535'
TARGET_SLUG='asteroids_jp_6.1.157-android14-11-g82d681c9b06b-ab14634535'
CORE='core61'
KSU_PIN='932014ab5b2c9b74a3d11e2ec4d17dd10fc9442e'
KSU_VERSION='32601'
KMI='android14-6.1'
KERNEL_RELEASE='6.1.157-android14-11-g82d681c9b06b-ab14634535'
DDK_IMAGE='ghcr.io/ylarod/ddk-min:android14-6.1-20260313'
MANAGER_PACKAGE='org.witaqua.pwn.kernelsu'
MANAGER_NAME='Root My Device KSU'
NDK_VERSION='29.0.14206865'
WORK="$ROOT/build/asteroids-fixed"
KSU_WORK="$WORK/KernelSU"
KERNELSU_SOURCE="$REPOSITORY_ROOT/src/kernelsu/KernelSU"
RMD="$REPOSITORY_ROOT/src/kernelsu/Root-My-Device-KSU"
APP_RELEASE=0

usage() {
  cat <<'USAGE'
Usage: ./tools/build-asteroids-fixed.sh [--release]

By default the script creates/reuses a LOCAL RSA-2048 Manager signing key under
build/asteroids-fixed/, compiles that certificate into kernelsu.ko, then builds
and signs a matching Root My Device KSU Manager. This avoids depending on a
private release key and prevents a Manager with a stale bundled ksud from
replacing the fixed daemon.

Environment overrides for an existing Manager key:
  RMD_MANAGER_KEYSTORE        absolute path to a JKS/PKCS12 keystore
  RMD_MANAGER_KEY_ALIAS       key alias
  RMD_MANAGER_STORE_PASSWORD  keystore password
  RMD_MANAGER_KEY_PASSWORD    key password

--release additionally builds Root My Nothing release APK and requires:
  RMN_KEYSTORE RMN_KEY_ALIAS RMN_STORE_PASSWORD RMN_KEY_PASSWORD
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --release) APP_RELEASE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

for cmd in git docker python3 cargo rustup java keytool sha256sum stat; do
  command -v "$cmd" >/dev/null || { echo "missing command: $cmd" >&2; exit 2; }
done

: "${ANDROID_HOME:?Set ANDROID_HOME to your Android SDK directory}"
NDK="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/$NDK_VERSION}"
[ -x "$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang" ] || {
  echo "NDK $NDK_VERSION not found at $NDK" >&2
  echo "Install it with: sdkmanager 'ndk;$NDK_VERSION'" >&2
  exit 2
}
export ANDROID_NDK_HOME="$NDK"

# Select one coherent SDK build-tools directory instead of assuming a local
# version number. The chosen zipalign must support 16 KiB page alignment.
resolve_android_build_tools() {
  local directory zipalign_help
  while IFS= read -r directory; do
    [ -x "$directory/aapt" ] || continue
    [ -x "$directory/apksigner" ] || continue
    [ -x "$directory/zipalign" ] || continue
    zipalign_help=$("$directory/zipalign" -h 2>&1 || true)
    case "$zipalign_help" in
      *"-P <pagesize_kb>"*"Valid values for <pagesize_kb> are 4, 16"*)
        printf '%s\n' "$directory"
        return 0
        ;;
    esac
  done < <(
    find "$ANDROID_HOME/build-tools" -mindepth 1 -maxdepth 1 -type d -print \
      2>/dev/null | sort -Vr
  )
  return 1
}

ANDROID_BUILD_TOOLS=$(resolve_android_build_tools) || {
  echo "no coherent Android SDK build-tools with aapt, apksigner, and zipalign -P 16 support found under $ANDROID_HOME/build-tools" >&2
  exit 2
}
export PATH="$ANDROID_BUILD_TOOLS:$PATH"
echo "==> Android build-tools: $ANDROID_BUILD_TOOLS"

mkdir -p "$WORK"

# ---------------------------------------------------------------------------
# Manager signer first: KernelSU authenticates its Manager by the APK signing
# certificate's DER size + SHA-256, so those values must be known before the
# module is compiled. Reuse the locally generated key across rebuilds.
# ---------------------------------------------------------------------------
LOCAL_MANAGER_KEYSTORE="$WORK/manager-signing.jks"
LOCAL_MANAGER_ENV="$WORK/manager-signing.env"

if [ -n "${RMD_MANAGER_KEYSTORE:-}" ]; then
  MANAGER_KEYSTORE=$(readlink -f "$RMD_MANAGER_KEYSTORE")
  MANAGER_KEY_ALIAS="${RMD_MANAGER_KEY_ALIAS:?Set RMD_MANAGER_KEY_ALIAS}"
  MANAGER_STORE_PASSWORD="${RMD_MANAGER_STORE_PASSWORD:?Set RMD_MANAGER_STORE_PASSWORD}"
  MANAGER_KEY_PASSWORD="${RMD_MANAGER_KEY_PASSWORD:?Set RMD_MANAGER_KEY_PASSWORD}"
  [ -f "$MANAGER_KEYSTORE" ] || { echo "Manager keystore not found: $MANAGER_KEYSTORE" >&2; exit 2; }
else
  MANAGER_KEYSTORE="$LOCAL_MANAGER_KEYSTORE"
  if [ ! -f "$MANAGER_KEYSTORE" ]; then
    MANAGER_KEY_ALIAS='root-my-device-local'
    MANAGER_STORE_PASSWORD=$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(36))
PY
)
    MANAGER_KEY_PASSWORD="$MANAGER_STORE_PASSWORD"
    keytool -genkeypair -noprompt \
      -keystore "$MANAGER_KEYSTORE" \
      -storetype PKCS12 \
      -storepass "$MANAGER_STORE_PASSWORD" \
      -keypass "$MANAGER_KEY_PASSWORD" \
      -alias "$MANAGER_KEY_ALIAS" \
      -keyalg RSA -keysize 2048 -validity 3650 \
      -dname 'CN=Root My Device KSU Local,O=Local Build,C=JP' >/dev/null
    umask 077
    cat > "$LOCAL_MANAGER_ENV" <<ENV
MANAGER_KEY_ALIAS='$MANAGER_KEY_ALIAS'
MANAGER_STORE_PASSWORD='$MANAGER_STORE_PASSWORD'
MANAGER_KEY_PASSWORD='$MANAGER_KEY_PASSWORD'
ENV
    chmod 600 "$LOCAL_MANAGER_ENV"
    echo "==> generated local Manager signing key: $MANAGER_KEYSTORE"
    echo "    Back up both manager-signing.jks and manager-signing.env if you want future builds to update the same Manager install."
  else
    [ -f "$LOCAL_MANAGER_ENV" ] || {
      echo "Found $LOCAL_MANAGER_KEYSTORE but not $LOCAL_MANAGER_ENV" >&2
      echo "Provide RMD_MANAGER_* variables or restore manager-signing.env" >&2
      exit 2
    }
    # shellcheck disable=SC1090
    source "$LOCAL_MANAGER_ENV"
  fi
fi

CERT_DER="$WORK/manager-cert.der"
keytool -exportcert -noprompt \
  -keystore "$MANAGER_KEYSTORE" \
  -storepass "$MANAGER_STORE_PASSWORD" \
  -alias "$MANAGER_KEY_ALIAS" \
  -file "$CERT_DER" >/dev/null
MANAGER_CERT_SIZE_DEC=$(stat -c '%s' "$CERT_DER")
[ "$MANAGER_CERT_SIZE_DEC" -le 1024 ] || {
  echo "Manager certificate is $MANAGER_CERT_SIZE_DEC bytes; KernelSU accepts at most 1024" >&2
  exit 3
}
printf -v MANAGER_CERT_SIZE '0x%04x' "$MANAGER_CERT_SIZE_DEC"
MANAGER_CERT_HASH=$(sha256sum "$CERT_DER" | awk '{print $1}')
echo "==> Manager signer: size=$MANAGER_CERT_SIZE ($MANAGER_CERT_SIZE_DEC) sha256=$MANAGER_CERT_HASH"

# ---------------------------------------------------------------------------
# Patch the exact pinned KernelSU tree.
# ---------------------------------------------------------------------------
[ -d "$RMD/patches/$KSU_VERSION/common" ] || {
  echo "missing shared KernelSU common patches: $RMD/patches/$KSU_VERSION/common" >&2
  exit 2
}
[ -d "$RMD/patches/$KSU_VERSION/devices/asteroids" ] || {
  echo "missing Nothing Phone (3a) device patches: $RMD/patches/$KSU_VERSION/devices/asteroids" >&2
  exit 2
}
RMD_PATCH_COMMIT='untracked-source'
if git -C "$RMD" rev-parse --git-dir >/dev/null 2>&1; then
  RMD_PATCH_COMMIT=$(git -C "$RMD" rev-parse HEAD)
  [ -z "$(git -C "$RMD" status --porcelain --untracked-files=all)" ] || {
    echo "Root-My-Device-KSU submodule is dirty; commit/pin the 32601 port before release builds" >&2
    exit 2
  }
  echo "==> Root-My-Device-KSU: $RMD_PATCH_COMMIT"
fi

rm -rf "$KSU_WORK"
if git -C "$KERNELSU_SOURCE" rev-parse --git-dir >/dev/null 2>&1; then
  git clone --quiet "$KERNELSU_SOURCE" "$KSU_WORK"
else
  echo "==> shared KernelSU submodule is not initialized; cloning pinned upstream"
  git clone --quiet https://github.com/tiann/KernelSU.git "$KSU_WORK"
fi
git -C "$KSU_WORK" checkout --quiet "$KSU_PIN"
actual=$((30000 + $(git -C "$KSU_WORK" rev-list --count HEAD)))
[ "$actual" = "$KSU_VERSION" ] || {
  echo "KernelSU history is shallow/wrong: version=$actual, expected=$KSU_VERSION" >&2
  exit 3
}

DEVICE_PATCHES=(
  "$RMD/patches/$KSU_VERSION/devices/asteroids/0001-recreate-zygote-boundary.patch"
  "$RMD/patches/$KSU_VERSION/devices/asteroids/0002-vector-toybox-unshare.patch"
  "$RMD/patches/$KSU_VERSION/devices/asteroids/0003-refresh-manager-after-late-load.patch"
)
PATCH_NORMALIZED="$WORK/normalized-patches"
rm -rf "$PATCH_NORMALIZED"
mkdir -p "$PATCH_NORMALIZED"
patch_index=0
for p in "$RMD/patches/$KSU_VERSION/common"/*.patch "${DEVICE_PATCHES[@]}"; do
  echo "==> apply $(basename "$p")"
  patch_index=$((patch_index + 1))
  normalized="$PATCH_NORMALIZED/${patch_index}-$(basename "$p")"
  # Patch files are text. Normalize a CRLF checkout before feeding it to
  # git-apply; otherwise every context line contains a literal CR and the
  # exact pinned Linux checkout will reject an otherwise-correct patch.
  sed 's/\r$//' "$p" > "$normalized"
  git -C "$KSU_WORK" apply --check "$normalized"
  git -C "$KSU_WORK" apply "$normalized"
done
git -C "$KSU_WORK" diff --check

# Build the target-matched LKM in the pinned Android 14/6.1 DDK.
echo "==> build kernelsu.ko"
docker pull "$DDK_IMAGE" >/dev/null
docker run --rm \
  -v "$ROOT:/workspace" -w /workspace \
  -e KERNEL_RELEASE="$KERNEL_RELEASE" \
  -e TARGET_CONFIG='' \
  -e KSU_MANAGER_PACKAGE="$MANAGER_PACKAGE" \
  -e KSU_EXPECTED_SIZE="$MANAGER_CERT_SIZE" \
  -e KSU_EXPECTED_HASH="$MANAGER_CERT_HASH" \
  "$DDK_IMAGE" \
  bash /workspace/tools/kernel/build-ddk-module.sh "/workspace/build/asteroids-fixed/KernelSU"
# The DDK container runs as root; hand the checkout back to the host user.
docker run --rm -v "$KSU_WORK:/ksu" "$DDK_IMAGE" \
  chown -R "$(id -u):$(id -g)" /ksu

TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64"
"$TOOLCHAIN/bin/llvm-strip" -d "$KSU_WORK/kernel/kernelsu.ko"
mkdir -p "$KSU_WORK/userspace/ksud/bin/aarch64"
cp "$KSU_WORK/kernel/kernelsu.ko" "$KSU_WORK/userspace/ksud/bin/aarch64/${KMI}_kernelsu.ko"

# Build the exact patched ksud that embeds the exact patched LKM.
echo "==> build ksud"
rustup target add aarch64-linux-android
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$TOOLCHAIN/bin/aarch64-linux-android35-clang"
export CC_aarch64_linux_android="$TOOLCHAIN/bin/aarch64-linux-android35-clang"
export AR_aarch64_linux_android="$TOOLCHAIN/bin/llvm-ar"
export LIBCLANG_PATH="$TOOLCHAIN/lib"
export BINDGEN_EXTRA_CLANG_ARGS_aarch64_linux_android="--target=aarch64-linux-android35 --sysroot=$TOOLCHAIN/sysroot"
# Cargo otherwise embeds the builder's home directory in panic/source paths.
# Encoded flags preserve paths containing spaces and keep published binaries
# free of workstation-specific usernames and checkout locations.
unset RUSTFLAGS
export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$HOME=/build/home"$'\x1f'"--remap-path-prefix=$KSU_WORK=/build/KernelSU"
cargo build --release --target aarch64-linux-android -p ksud \
  --manifest-path "$KSU_WORK/Cargo.toml"
cp "$KSU_WORK/target/aarch64-linux-android/release/ksud" "$WORK/ksud-asteroids"
if grep -aFq "$HOME/" "$WORK/ksud-asteroids"; then
  echo "built ksud still contains the builder home path" >&2
  exit 4
fi

# Sanity markers that distinguish this fixed ksud from the old one.
for marker in 'late-load compatibility' 'recreating zygote-start boundary' 'Vector service launcher installed with absolute Android tools' 'one monitored direct service launch' 'launching Vector directly with /system/bin/sh' 'Vector root daemon socket registered' 'Vector CLI framework health verified' 'KernelSU Manager restarted after late-load'; do
  grep -qa "$marker" "$WORK/ksud-asteroids" || {
    echo "built ksud is missing marker: $marker" >&2; exit 4; }
done

# Build a Manager that carries THIS patched ksud and is signed with the exact
# certificate compiled into kernelsu.ko. Otherwise opening the Manager can put
# a stale /data/adb/ksud back on the device.
echo "==> build signer-matched Root My Device KSU Manager"
cat >> "$KSU_WORK/manager/gradle.properties" <<PROPS
KEYSTORE_FILE=$MANAGER_KEYSTORE
KEYSTORE_PASSWORD=$MANAGER_STORE_PASSWORD
KEY_ALIAS=$MANAGER_KEY_ALIAS
KEY_PASSWORD=$MANAGER_KEY_PASSWORD
PROPS
(
  cd "$KSU_WORK/manager"
  ./gradlew clean assembleRelease \
    -PKSU_PACKAGE_NAME="$MANAGER_PACKAGE" -PKSU_NAME="$MANAGER_NAME"
)
rm -rf "$WORK/manager-dist"
mkdir -p "$WORK/manager-dist"
python3 "$KSU_WORK/repack_apk.py" repack \
  -b release -t release -a arm64-v8a \
  -K "$MANAGER_KEYSTORE" -A "$MANAGER_KEY_ALIAS" \
  -P "$MANAGER_STORE_PASSWORD" -S "$MANAGER_KEY_PASSWORD" \
  -n "RootMyDeviceKSU_${KSU_VERSION}_Asteroids_v1.2" \
  -o "$WORK/manager-dist"
MANAGER_APK=$(find "$WORK/manager-dist" -maxdepth 1 -type f -name '*.apk' | head -n 1)
[ -n "$MANAGER_APK" ] || { echo "Manager repack produced no APK" >&2; exit 4; }

# The plain Gradle APK intentionally has no ksud payload; only repack_apk.py's
# paired artifact is safe to install. Refuse to publish a Manager that omits or
# embeds a different daemon, since its module CLI would silently report `[]`.
python3 - "$MANAGER_APK" "$WORK/ksud-asteroids" <<'PY'
import hashlib
import sys
import zipfile

apk, ksud = sys.argv[1:]
entry = "lib/arm64-v8a/libksud.so"
with zipfile.ZipFile(apk) as archive:
    try:
        embedded = archive.read(entry)
    except KeyError as error:
        raise SystemExit(f"paired Manager is missing {entry}") from error
expected = open(ksud, "rb").read()
if hashlib.sha256(embedded).digest() != hashlib.sha256(expected).digest():
    raise SystemExit("paired Manager libksud.so does not match the patched ksud")
PY

# Assert that the final APK signer is exactly the certificate compiled into
# kernelsu.ko. Do not depend on one exact apksigner label: newer apksigner
# versions may describe a signer as "Signer (minSdkVersion=...)" rather than
# "Signer #1". Parse any signer certificate SHA-256 line and normalize case.
APKSIGNER="$ANDROID_BUILD_TOOLS/apksigner"
if ! APKSIGNER_CERT_OUTPUT=$(
  "$APKSIGNER" verify --print-certs "$MANAGER_APK" 2>&1
); then
  echo "apksigner failed while verifying the repacked Manager:" >&2
  printf '%s\n' "$APKSIGNER_CERT_OUTPUT" >&2
  exit 4
fi

GOT_CERT=$(printf '%s\n' "$APKSIGNER_CERT_OUTPUT" | awk '
  {
    line=$0
    sub(/\r$/, "", line)
    lower=tolower(line)
    marker="certificate sha-256 digest:"
    marker_pos=index(lower, marker)
    if (marker_pos > 0) {
      digest=substr(line, marker_pos + length(marker))
      gsub(/[^0-9A-Fa-f]/, "", digest)
      if (length(digest) == 64) {
        print tolower(digest)
        exit
      }
    }
  }
')
EXPECTED_CERT=$(printf '%s' "$MANAGER_CERT_HASH" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')

[ -n "$GOT_CERT" ] || {
  echo "Could not parse Manager signer SHA-256 from apksigner output:" >&2
  printf '%s\n' "$APKSIGNER_CERT_OUTPUT" >&2
  exit 4
}
[ "$GOT_CERT" = "$EXPECTED_CERT" ] || {
  echo "Manager signer mismatch: got=$GOT_CERT expected=$EXPECTED_CERT" >&2
  exit 4
}

# Build the exploit standalone payload and the fixed bootstrap helper/daemon.
echo "==> build exploit + root helper"
make -C "$ROOT" TARGET="$TARGET" CORE="$CORE" all

# Copy all three new binaries into the app and update its byte-size/hash pins.
echo "==> sync app artifacts"
python3 "$ROOT/tools/sync-asteroids-app-artifacts.py" \
  --payload "$ROOT/build/$TARGET_SLUG/cve-2026-43499-standalone" \
  --helper "$ROOT/build/$TARGET_SLUG/cve-2026-43499-root" \
  --ksud "$WORK/ksud-asteroids"

# The debug build needs no private app signing key. For release, Gradle picks up
# the RMN_* signing variables already supported by app/build.gradle.kts.
echo "==> build Root My Nothing APK"
cd "$ROOT"
if [ "$APP_RELEASE" -eq 1 ]; then
  : "${RMN_KEYSTORE:?Set RMN_KEYSTORE for --release}"
  : "${RMN_KEY_ALIAS:?Set RMN_KEY_ALIAS for --release}"
  : "${RMN_STORE_PASSWORD:?Set RMN_STORE_PASSWORD for --release}"
  : "${RMN_KEY_PASSWORD:?Set RMN_KEY_PASSWORD for --release}"
  ./gradlew --no-daemon --no-configuration-cache :app:assembleRelease
  APP_APK="$ROOT/app/build/outputs/apk/release/app-release.apk"
else
  ./gradlew --no-daemon --no-configuration-cache :app:assembleDebug
  APP_APK="$ROOT/app/build/outputs/apk/debug/app-debug.apk"
fi

if [ "$APP_RELEASE" -eq 1 ]; then
  "$APKSIGNER" verify --verbose "$APP_APK" >/dev/null
fi

APP_HASH=$(sha256sum "$APP_APK" | awk '{print $1}')
MANAGER_APK_HASH=$(sha256sum "$MANAGER_APK" | awk '{print $1}')
KSUD_HASH=$(sha256sum "$WORK/ksud-asteroids" | awk '{print $1}')
MODULE_HASH=$(sha256sum "$KSU_WORK/kernel/kernelsu.ko" | awk '{print $1}')
MANIFEST="$WORK/build-manifest.txt"
printf '%s\n' \
  "target=$TARGET" \
  "kernel_release=$KERNEL_RELEASE" \
  "kmi=$KMI" \
  "ksu_pin=$KSU_PIN" \
  "ksu_version=$KSU_VERSION" \
  "rmd_patch_commit=$RMD_PATCH_COMMIT" \
  "manager_certificate_size=$MANAGER_CERT_SIZE_DEC" \
  "manager_certificate_sha256=$MANAGER_CERT_HASH" \
  "kernelsu=$MODULE_HASH $KSU_WORK/kernel/kernelsu.ko" \
  "ksud=$KSUD_HASH $WORK/ksud-asteroids" \
  "manager_apk=$MANAGER_APK_HASH $MANAGER_APK" \
  "app_apk=$APP_HASH $APP_APK" > "$MANIFEST"

cat <<DONE

Build complete.
Root My Nothing: $APP_APK
Root My Device KSU: $MANAGER_APK
ksud:  $WORK/ksud-asteroids
ko:    $KSU_WORK/kernel/kernelsu.ko
manifest: $MANIFEST
Manager signer SHA-256: $MANAGER_CERT_HASH
Manager signer DER size: $MANAGER_CERT_SIZE_DEC
DONE
