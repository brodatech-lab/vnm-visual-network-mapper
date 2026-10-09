#!/usr/bin/env bash
#
# VNM installer for Linux: installs dependencies, downloads the sources (when run
# standalone) and builds + installs the app.
#
# Quick install (fetches this script and runs it):
#
#   curl -fsSL https://raw.githubusercontent.com/brodatech-lab/vnm-visual-network-mapper/main/install.sh | bash
#
# Or from a checkout:
#
#   ./install.sh
#
# Options:
#   --no-deps        skip installing system dependencies
#   --no-setcap      skip granting raw-socket capabilities
#   --prefix <dir>   install prefix (default: /usr/local)
#
set -euo pipefail

REPO="brodatech-lab/vnm-visual-network-mapper"
BRANCH="${VNM_BRANCH:-main}"
PREFIX="${VNM_PREFIX:-/usr/local}"
DO_DEPS=1
DO_SETCAP=1

while [ $# -gt 0 ]; do
    case "$1" in
        --no-deps)   DO_DEPS=0 ;;
        --no-setcap) DO_SETCAP=0 ;;
        --prefix)    PREFIX="${2:?--prefix needs a value}"; shift ;;
        -h|--help)   sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)           echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

log() { printf '\033[1;32m[vnm]\033[0m %s\n' "$*"; }

ROOT=""
[ "$(id -u)" -ne 0 ] && ROOT="sudo"

# Use sudo for file installs only when the prefix is not writable by us.
SUDO="$ROOT"
if [ "$(id -u)" -ne 0 ]; then
    if mkdir -p "$PREFIX/bin" 2>/dev/null && [ -w "$PREFIX/bin" ]; then
        SUDO=""
    fi
fi

# Locate the sources: use the current checkout if present, otherwise download.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
SRC=""
if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/CMakeLists.txt" ]; then
    SRC="$SCRIPT_DIR"
fi

if [ -z "$SRC" ]; then
    TMP="$(mktemp -d)"
    if command -v git >/dev/null 2>&1; then
        log "cloning https://github.com/$REPO ($BRANCH)..."
        git clone --depth 1 --branch "$BRANCH" "https://github.com/$REPO.git" "$TMP/vnm"
    else
        log "downloading $BRANCH tarball..."
        mkdir -p "$TMP/vnm"
        curl -fsSL "https://github.com/$REPO/archive/refs/heads/$BRANCH.tar.gz" \
            | tar -xz -C "$TMP/vnm" --strip-components=1
    fi
    SRC="$TMP/vnm"
fi
log "sources: $SRC"

# Dependencies (Debian/Ubuntu).
if [ "$DO_DEPS" -eq 1 ]; then
    if command -v apt-get >/dev/null 2>&1; then
        log "installing dependencies (apt)..."
        $ROOT apt-get update -qq
        $ROOT apt-get install -y --no-install-recommends \
            build-essential cmake pkg-config git nmap \
            libsqlite3-dev libpcap-dev \
            libglfw3-dev libgl1-mesa-dev libx11-dev libxkbcommon-dev libwayland-dev
    else
        log "apt-get not found: install cmake, a C++20 compiler, nmap, libsqlite3-dev,"
        log "libpcap-dev, libglfw3-dev and OpenGL/X11 dev packages manually, then rerun."
    fi
fi

# Build (Release, GUI on).
BUILD_DIR="$SRC/build/release"
log "configuring & building (Release)..."
cmake -S "$SRC" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release -DVNM_BUILD_GUI=ON
cmake --build "$BUILD_DIR" -j"$(nproc 2>/dev/null || echo 2)"

# Install binaries.
log "installing to $PREFIX/bin ..."
$SUDO install -Dm755 "$BUILD_DIR/vnm" "$PREFIX/bin/vnm"
$SUDO install -Dm755 "$BUILD_DIR/src/ui/vnm_gui" "$PREFIX/bin/vnm_gui"

# Desktop entry + icon (best effort).
[ -f "$SRC/packaging/vnm.desktop" ] && \
    $SUDO install -Dm644 "$SRC/packaging/vnm.desktop" "$PREFIX/share/applications/vnm.desktop"
[ -f "$SRC/assets/vnm.png" ] && \
    $SUDO install -Dm644 "$SRC/assets/vnm.png" \
        "$PREFIX/share/icons/hicolor/256x256/apps/vnm.png"

# Raw-socket capabilities so passive ARP/DHCP capture works without root.
if [ "$DO_SETCAP" -eq 1 ]; then
    SETCAP="$(command -v setcap || true)"
    [ -z "$SETCAP" ] && [ -x /usr/sbin/setcap ] && SETCAP=/usr/sbin/setcap
    if [ -n "$SETCAP" ]; then
        log "granting capture capabilities (setcap)..."
        $ROOT "$SETCAP" cap_net_raw,cap_net_admin+eip "$PREFIX/bin/vnm_gui" || \
            log "setcap failed (filesystem may not support xattrs)"
        $ROOT "$SETCAP" cap_net_raw,cap_net_admin+eip "$PREFIX/bin/vnm" || true
    fi
fi

log "done."
echo "  run the GUI : vnm_gui"
echo "  run the CLI : vnm --help"
