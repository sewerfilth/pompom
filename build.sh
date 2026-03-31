#!/bin/bash
# pompom build script — cross-platform, cross-architecture
#
# Usage:
#   ./build.sh                    # native build (auto-detect)
#   ./build.sh --target x86_64-linux
#   ./build.sh --target libnx
#   ./build.sh --test             # build + run tests
#   ./build.sh --stress           # build + run stress/pentests
#   ./build.sh --examples         # build host + client
#   ./build.sh --all              # build everything
#   ./build.sh --clean
#   ./build.sh --list-targets
#
# Targets:
#   aarch64-darwin   macOS Apple Silicon
#   x86_64-darwin    macOS Intel
#   x86_64-linux     Linux x64 (AMD + Intel)
#   i686-linux       Linux x86 32-bit
#   aarch64-linux    Linux ARM64
#   libnx            Nintendo Switch

set -e
cd "$(dirname "$0")"

TOOLCHAINS="../shared/toolchains"
TARGET=""
ACTION="build"

# ── Parse args ───────────────────────────────────────────────────────

while [ $# -gt 0 ]; do
    case "$1" in
        --target|-t)    TARGET="$2"; shift 2 ;;
        --test)         ACTION="test"; shift ;;
        --stress)       ACTION="stress"; shift ;;
        --examples)     ACTION="examples"; shift ;;
        --all)          ACTION="all"; shift ;;
        --clean)        make clean; exit 0 ;;
        --list-targets) ls "$TOOLCHAINS"/*.mk 2>/dev/null | sed 's|.*/||;s|\.mk||' | sort -u; exit 0 ;;
        --help|-h)
            sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
            exit 0 ;;
        *)  echo "unknown option: $1"; exit 1 ;;
    esac
done

# ── Build ────────────────────────────────────────────────────────────

MAKE_ARGS=""

if [ -n "$TARGET" ]; then
    MK="$TOOLCHAINS/$TARGET.mk"
    if [ ! -f "$MK" ]; then
        echo "error: unknown target '$TARGET'"
        echo "available: $($0 --list-targets | tr '\n' ' ')"
        exit 1
    fi

    # Map target to ARCH
    case "$TARGET" in
        aarch64-darwin|aarch64-linux|libnx) ARCH=arm ;;
        x86_64-darwin|x86_64-linux)         ARCH=x86_64 ;;
        i686-linux)                         ARCH=x86_32 ;;
    esac

    MAKE_ARGS="ARCH=$ARCH TOOLCHAIN=$MK BUILDDIR=build/$TARGET"
    echo "target: $TARGET"
fi

case "$ACTION" in
    build)    make $MAKE_ARGS ;;
    test)     make $MAKE_ARGS test ;;
    stress)   make $MAKE_ARGS stress ;;
    examples) make $MAKE_ARGS examples ;;
    all)      make $MAKE_ARGS && make $MAKE_ARGS test && make $MAKE_ARGS stress && make $MAKE_ARGS examples ;;
esac

echo "done."
