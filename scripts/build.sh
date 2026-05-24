#!/usr/bin/env sh
set -eu

VERSION="${1:-dev}"
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
DIST="$ROOT/dist"
mkdir -p "$DIST"

build() {
  goos="$1"
  goarch="$2"
  ext="$3"
  cgo="${4:-0}"
  cc="${5:-}"
  name="cfip-${goos}-${goarch}${ext}"
  echo "Building $name"
  CGO_ENABLED="$cgo" GOOS="$goos" GOARCH="$goarch" CC="$cc" \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$DIST/$name" .
}

cd "$ROOT"
build windows amd64 .exe
build linux amd64 ""
build darwin amd64 ""

if [ "${SKIP_ANDROID:-0}" != "1" ]; then
  android_cc="${ANDROID_CC:-}"
  if [ -z "$android_cc" ] && [ -n "${ANDROID_NDK_HOME:-}" ]; then
    case "$(uname -s)" in
      Linux*) host_tag="linux-x86_64" ;;
      Darwin*) host_tag="darwin-x86_64" ;;
      *) host_tag="windows-x86_64" ;;
    esac
    android_cc="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$host_tag/bin/x86_64-linux-android21-clang"
  fi
  if [ -z "$android_cc" ] || [ ! -x "$android_cc" ]; then
    echo "android/amd64 requires Android NDK. Set ANDROID_NDK_HOME or ANDROID_CC, or run with SKIP_ANDROID=1." >&2
    exit 1
  fi
  build android amd64 "" 1 "$android_cc"
fi

if command -v zip >/dev/null 2>&1; then
  (cd "$DIST" && zip -q -r "cfip-$VERSION-all.zip" cfip-*)
fi

echo "Done: $DIST"
