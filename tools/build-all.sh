#!/usr/bin/env bash
# Build the Nothing Phone (3a) and OnePlus Pad 3 release sets in one command.
# Existing per-device signing variables remain supported. Optionally, one
# ROOT_MY_DEVICE_* identity can populate every missing signing variable.
set -euo pipefail

# Never allow an inherited xtrace setting to print signing credentials.
case "$-" in
  *x*) set +x; echo "[!] disabled shell xtrace before handling signing variables" >&2 ;;
esac

REPOSITORY_ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD_NOTHING=1
BUILD_ONEPLUS=1
RELEASE_CONFIRMED=0
PLAN_ONLY=0
VERIFY_ONEPLUS=0
ONEPLUS_SERIAL=''

usage() {
  cat <<'USAGE'
Usage: ./tools/build-all.sh --release [options]

Builds both exact-device release sets sequentially from the shared pinned
KernelSU and Root-My-Device-KSU submodules.

Options:
  --release                    required explicit release confirmation
  --nothing-only               build only Nothing Phone (3a)
  --oneplus-only               build only OnePlus Pad 3
  --verify-oneplus-device      run the OnePlus read-only exact-device guard
  --oneplus-serial SERIAL      select a connected OnePlus device for that guard
  --plan                       validate configuration and print commands only
  -h, --help                   show this help

Existing per-device signing environment:
  Nothing Manager: RMD_MANAGER_KEYSTORE, RMD_MANAGER_KEY_ALIAS,
                   RMD_MANAGER_STORE_PASSWORD, RMD_MANAGER_KEY_PASSWORD
  Nothing Root app: RMN_KEYSTORE, RMN_KEY_ALIAS,
                    RMN_STORE_PASSWORD, RMN_KEY_PASSWORD
  OnePlus both APKs: RMOP_KEYSTORE, RMOP_KEY_ALIAS,
                     RMOP_STORE_PASSWORD, RMOP_KEY_PASSWORD,
                     or RMOP_PASSWORD_FILE

Optional one-key shorthand (fills only variables that are not already set):
  ROOT_MY_DEVICE_KEYSTORE
  ROOT_MY_DEVICE_KEY_ALIAS
  ROOT_MY_DEVICE_STORE_PASSWORD
  ROOT_MY_DEVICE_KEY_PASSWORD   defaults to ROOT_MY_DEVICE_STORE_PASSWORD

Example:
  export ANDROID_HOME="$HOME/Android/Sdk"
  export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/29.0.14206865"
  export ROOT_MY_DEVICE_KEYSTORE=/absolute/path/release-signing.p12
  export ROOT_MY_DEVICE_KEY_ALIAS=key0
  export ROOT_MY_DEVICE_STORE_PASSWORD='...'
  export ROOT_MY_DEVICE_KEY_PASSWORD='...'
  ./tools/build-all.sh --release

The script does not print passwords, install APKs, flash, reboot, unlock, or
wipe a device. The optional OnePlus verification reads properties/boot state.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --release)
      RELEASE_CONFIRMED=1
      ;;
    --nothing-only)
      BUILD_NOTHING=1
      BUILD_ONEPLUS=0
      ;;
    --oneplus-only)
      BUILD_NOTHING=0
      BUILD_ONEPLUS=1
      ;;
    --verify-oneplus-device)
      VERIFY_ONEPLUS=1
      ;;
    --oneplus-serial)
      [ "$#" -ge 2 ] || { echo "--oneplus-serial requires a value" >&2; exit 2; }
      ONEPLUS_SERIAL=$2
      VERIFY_ONEPLUS=1
      shift
      ;;
    --plan)
      PLAN_ONLY=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

[ "$RELEASE_CONFIRMED" -eq 1 ] || {
  echo "--release is required for the combined signer-aware build" >&2
  usage >&2
  exit 2
}

[ "$BUILD_NOTHING" -eq 1 ] || [ "$BUILD_ONEPLUS" -eq 1 ] || {
  echo "no device was selected" >&2
  exit 2
}

# Map a single explicit identity to all missing device-specific variables.
if [ -n "${ROOT_MY_DEVICE_KEYSTORE:-}" ]; then
  : "${ROOT_MY_DEVICE_KEY_ALIAS:?Set ROOT_MY_DEVICE_KEY_ALIAS}"
  : "${ROOT_MY_DEVICE_STORE_PASSWORD:?Set ROOT_MY_DEVICE_STORE_PASSWORD}"
  ROOT_MY_DEVICE_KEY_PASSWORD=${ROOT_MY_DEVICE_KEY_PASSWORD:-$ROOT_MY_DEVICE_STORE_PASSWORD}

  export RMD_MANAGER_KEYSTORE=${RMD_MANAGER_KEYSTORE:-$ROOT_MY_DEVICE_KEYSTORE}
  export RMD_MANAGER_KEY_ALIAS=${RMD_MANAGER_KEY_ALIAS:-$ROOT_MY_DEVICE_KEY_ALIAS}
  export RMD_MANAGER_STORE_PASSWORD=${RMD_MANAGER_STORE_PASSWORD:-$ROOT_MY_DEVICE_STORE_PASSWORD}
  export RMD_MANAGER_KEY_PASSWORD=${RMD_MANAGER_KEY_PASSWORD:-$ROOT_MY_DEVICE_KEY_PASSWORD}

  export RMN_KEYSTORE=${RMN_KEYSTORE:-$ROOT_MY_DEVICE_KEYSTORE}
  export RMN_KEY_ALIAS=${RMN_KEY_ALIAS:-$ROOT_MY_DEVICE_KEY_ALIAS}
  export RMN_STORE_PASSWORD=${RMN_STORE_PASSWORD:-$ROOT_MY_DEVICE_STORE_PASSWORD}
  export RMN_KEY_PASSWORD=${RMN_KEY_PASSWORD:-$ROOT_MY_DEVICE_KEY_PASSWORD}

  export RMOP_KEYSTORE=${RMOP_KEYSTORE:-$ROOT_MY_DEVICE_KEYSTORE}
  export RMOP_KEY_ALIAS=${RMOP_KEY_ALIAS:-$ROOT_MY_DEVICE_KEY_ALIAS}
  export RMOP_STORE_PASSWORD=${RMOP_STORE_PASSWORD:-$ROOT_MY_DEVICE_STORE_PASSWORD}
  export RMOP_KEY_PASSWORD=${RMOP_KEY_PASSWORD:-$ROOT_MY_DEVICE_KEY_PASSWORD}
fi

require_set() {
  local name=$1
  [ -n "${!name:-}" ] || {
    echo "missing required signing variable: $name" >&2
    exit 2
  }
}

require_file_variable() {
  local name=$1
  local value directory absolute
  require_set "$name"
  value=${!name}
  [ -f "$value" ] || {
    echo "file from $name does not exist: $value" >&2
    exit 2
  }
  directory=$(cd "$(dirname "$value")" && pwd)
  absolute="$directory/$(basename "$value")"
  printf -v "$name" '%s' "$absolute"
  export "$name"
}

: "${ANDROID_HOME:?Set ANDROID_HOME to the Android SDK directory}"

if [ "$BUILD_NOTHING" -eq 1 ]; then
  # The Nothing Manager may still use its build-local generated key when no
  # RMD_MANAGER_* identity is supplied, matching the original device script.
  require_file_variable RMN_KEYSTORE
  require_set RMN_KEY_ALIAS
  require_set RMN_STORE_PASSWORD
  require_set RMN_KEY_PASSWORD
  if [ -n "${RMD_MANAGER_KEYSTORE:-}" ]; then
    require_file_variable RMD_MANAGER_KEYSTORE
    require_set RMD_MANAGER_KEY_ALIAS
    require_set RMD_MANAGER_STORE_PASSWORD
    require_set RMD_MANAGER_KEY_PASSWORD
  fi
fi

if [ "$BUILD_ONEPLUS" -eq 1 ]; then
  require_file_variable RMOP_KEYSTORE
  require_set RMOP_KEY_ALIAS
  if [ -n "${RMOP_STORE_PASSWORD:-}" ]; then
    export RMOP_KEY_PASSWORD=${RMOP_KEY_PASSWORD:-$RMOP_STORE_PASSWORD}
  elif [ -n "${RMOP_PASSWORD_FILE:-}" ]; then
    require_file_variable RMOP_PASSWORD_FILE
  else
    echo "set RMOP_STORE_PASSWORD or RMOP_PASSWORD_FILE" >&2
    exit 2
  fi
fi

KSU_EXPECTED='b0bc817b4e966aa6aa830834eaf6ef765d821d40'
RMD_EXPECTED='bf5bfa9ba0e7430611cca4b55ab12885df2d4eaa'
for spec in \
  "src/kernelsu/KernelSU:$KSU_EXPECTED" \
  "src/kernelsu/Root-My-Device-KSU:$RMD_EXPECTED"; do
  path=${spec%%:*}
  expected=${spec#*:}
  [ -e "$REPOSITORY_ROOT/$path/.git" ] || {
    echo "submodule is not initialized: $path" >&2
    echo "Run: git submodule update --init --recursive" >&2
    exit 2
  }
  actual=$(git -C "$REPOSITORY_ROOT/$path" rev-parse HEAD)
  [ "$actual" = "$expected" ] || {
    echo "$path pin mismatch: $actual != $expected" >&2
    exit 2
  }
done

nothing_command=(bash "$REPOSITORY_ROOT/devices/nothing-phone-3a/tools/build-asteroids-fixed.sh" --release)
oneplus_command=(bash "$REPOSITORY_ROOT/devices/oneplus-pad-3/tools/build-oneplus-pad3.sh" --release)
if [ "$VERIFY_ONEPLUS" -eq 1 ]; then
  if [ -n "$ONEPLUS_SERIAL" ]; then
    oneplus_command+=(--serial "$ONEPLUS_SERIAL")
  else
    oneplus_command+=(--verify-device)
  fi
fi

print_command() {
  local number=$1
  local label=$2
  shift 2
  printf '  %s. %s:' "$number" "$label"
  printf ' %q' "$@"
  printf '\n'
}

printf '%s\n' "Root My Device combined release plan:"
step=1
if [ "$BUILD_NOTHING" -eq 1 ]; then
  print_command "$step" "Nothing Phone (3a)" "${nothing_command[@]}"
  step=$((step + 1))
fi
if [ "$BUILD_ONEPLUS" -eq 1 ]; then
  print_command "$step" "OnePlus Pad 3" "${oneplus_command[@]}"
fi
printf '%s\n' "  shared KernelSU: $KSU_EXPECTED" "  shared patches:  $RMD_EXPECTED"

[ "$PLAN_ONLY" -eq 0 ] || exit 0

export ROOT_MY_DEVICE_REPOSITORY_ROOT="$REPOSITORY_ROOT"

# A combined build should attempt every selected device even when an earlier
# device fails. Otherwise a Nothing failure prevents the OnePlus build from
# ever starting and makes the wrapper look like a Nothing-only build.
build_failures=()

run_device_build() {
  local label=$1
  local directory=$2
  shift 2

  echo "==> Building $label release set"
  if (cd "$directory" && "$@"); then
    echo "==> $label release set completed"
  else
    local rc=$?
    echo "[ERROR] $label release set failed with exit code $rc; continuing with remaining selected devices" >&2
    build_failures+=("$label:$rc")
  fi
}

if [ "$BUILD_NOTHING" -eq 1 ]; then
  run_device_build \
    "Nothing Phone (3a)" \
    "$REPOSITORY_ROOT/devices/nothing-phone-3a" \
    "${nothing_command[@]}"
fi

if [ "$BUILD_ONEPLUS" -eq 1 ]; then
  run_device_build \
    "OnePlus Pad 3" \
    "$REPOSITORY_ROOT/devices/oneplus-pad-3" \
    "${oneplus_command[@]}"
fi

if [ "${#build_failures[@]}" -ne 0 ]; then
  echo "==> Combined release build finished with failures:" >&2
  printf '  - %s\n' "${build_failures[@]}" >&2
  exit 1
fi

echo "==> Combined release build completed successfully"
