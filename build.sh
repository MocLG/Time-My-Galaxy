#!/usr/bin/env bash
# Build the APK. Debug is the default; release is signed with a keystore
# properties file.
#
#   ./build.sh                              debug APK
#   ./build.sh release                      release APK, default key
#   ./build.sh release /path/to/key.props   release APK, explicit key
#
# Release reads storeFile=, alias=, and password= from the given file, or from
# $KEYSTORE_PROPS, or from ~/.android/release-keystore.properties. It fails
# before Gradle starts if that file is missing.
#
# On an ARM64 host the SDK's x86-64 AAPT2 cannot run, so point Gradle at an
# aarch64 AAPT2 (for example the one under ~/android-sdk-tools/build-tools or
# the Debian android-sdk package).
set -euo pipefail

cd "$(dirname "$0")"

if [ -z "${JAVA_HOME:-}" ] && [ -d /usr/lib/jvm/java-21-openjdk-arm64 ]; then
  export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-arm64
fi

VARIANT="${1:-debug}"
case "$VARIANT" in
  debug|release)
    shift || true
    ;;
  *)
    echo "usage: $0 [debug|release] [keystore-properties]" >&2
    exit 2
    ;;
esac

KEYSTORE_ARGS=()
case "$VARIANT" in
  debug)
    TASK=":app:assembleDebug"
    OUT="app/build/outputs/apk/debug/app-debug.apk"
    ;;
  release)
    KEYSTORE_PROPS="${1:-${KEYSTORE_PROPS:-$HOME/.android/release-keystore.properties}}"
    if [ ! -f "$KEYSTORE_PROPS" ]; then
      echo "error: release signing properties not found: $KEYSTORE_PROPS" >&2
      echo "       provide one with: $0 release /path/to/keystore.properties" >&2
      exit 1
    fi
    KEYSTORE_ARGS+=("-PkeystoreProps=$(realpath "$KEYSTORE_PROPS")")
    TASK=":app:assembleRelease"
    OUT="app/build/outputs/apk/release/app-release.apk"
    shift || true
    ;;
esac

ARGS=("${KEYSTORE_ARGS[@]}")
if [ "$(uname -m)" = "aarch64" ] || [ "$(uname -m)" = "arm64" ]; then
  AAPT2="${AAPT2_OVERRIDE:-$HOME/android-sdk-tools/build-tools/aapt2}"
  if [ -x "$AAPT2" ]; then
    ARGS+=("-Pandroid.aapt2FromMavenOverride=$AAPT2")
  else
    echo "warning: no aarch64 aapt2 found; set AAPT2_OVERRIDE" >&2
  fi
fi

./gradlew "$TASK" "${ARGS[@]}" "$@"
echo "APK: $OUT"
