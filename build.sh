#!/usr/bin/env bash
# Build the debug APK. On an ARM64 host the SDK's x86-64 AAPT2 cannot run, so
# point Gradle at an aarch64 AAPT2 (for example the one under
# ~/android-sdk-tools/build-tools or the Debian android-sdk package).
set -euo pipefail

cd "$(dirname "$0")"

if [ -z "${JAVA_HOME:-}" ] && [ -d /usr/lib/jvm/java-21-openjdk-arm64 ]; then
  export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-arm64
fi

ARGS=()
if [ "$(uname -m)" = "aarch64" ] || [ "$(uname -m)" = "arm64" ]; then
  AAPT2="${AAPT2_OVERRIDE:-$HOME/android-sdk-tools/build-tools/aapt2}"
  if [ -x "$AAPT2" ]; then
    ARGS+=("-Pandroid.aapt2FromMavenOverride=$AAPT2")
  else
    echo "warning: no aarch64 aapt2 found; set AAPT2_OVERRIDE" >&2
  fi
fi

exec ./gradlew :app:assembleDebug "${ARGS[@]}" "$@"
