#!/bin/bash
#
# build.sh — Build everything: kernel + vulnerable modules + initramfs
#
# This downloads Linux 6.1.75, compiles it, builds all 5 vulnerable
# kernel modules, and creates initramfs images for each challenge.
#
# Requirements (Ubuntu 22.04 / 24.04):
#   sudo apt install -y gcc make flex bison bc libelf-dev libssl-dev \
#                       busybox-static cpio wget
#
# Usage:
#   ./build.sh              # Full build (kernel + modules + initramfs)
#   ./build.sh modules      # Modules + initramfs only (needs existing kernel)
#   ./build.sh initramfs    # Initramfs only (needs existing modules)
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KERNEL_VERSION="6.1.75"
KERNEL_DIR="$SCRIPT_DIR/linux-$KERNEL_VERSION"
JOBS="$(nproc)"

# Challenge flags — loaded from .flags (not tracked by git)
FLAGS_FILE="$SCRIPT_DIR/.flags"
if [ ! -f "$FLAGS_FILE" ]; then
    echo "[!] .flags file not found."
    echo "    Create it from the template:  cp .flags.example .flags"
    echo "    Then edit .flags with your actual flag values."
    exit 1
fi
source "$FLAGS_FILE"

for var in FLAG_CH01 FLAG_CH02 FLAG_CH03 FLAG_CH04 FLAG_CH05; do
    if [ -z "${!var}" ]; then
        echo "[!] $var is not set in .flags"
        exit 1
    fi
done

# ---- Dependency check ----
check_deps() {
    local missing=()
    for cmd in gcc make flex bison bc cpio; do
        which "$cmd" &>/dev/null || missing+=("$cmd")
    done
    which busybox &>/dev/null || which busybox-static &>/dev/null || missing+=("busybox-static")

    if ! pkg-config --exists libelf 2>/dev/null; then
        # Check if header exists directly
        [ -f /usr/include/libelf.h ] || [ -f /usr/include/gelf.h ] || missing+=("libelf-dev")
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        echo "[!] Missing dependencies: ${missing[*]}"
        echo "    Install: sudo apt install -y ${missing[*]}"
        exit 1
    fi
    echo "[+] All dependencies found."
}

# ---- Build kernel ----
build_kernel() {
    echo ""
    echo "============================================"
    echo "  Building Linux $KERNEL_VERSION"
    echo "============================================"

    if [ ! -d "$KERNEL_DIR" ]; then
        local tarball="linux-${KERNEL_VERSION}.tar.xz"
        if [ ! -f "$tarball" ]; then
            echo "[*] Downloading kernel source..."
            wget -q --show-progress \
                "https://cdn.kernel.org/pub/linux/kernel/v6.x/$tarball"
        fi
        echo "[*] Extracting..."
        tar xf "$tarball"
    fi

    cd "$KERNEL_DIR"

    if [ ! -f ".config" ]; then
        echo "[*] Configuring kernel..."
        make defconfig
        scripts/config \
            -e CONFIG_DEBUG_INFO \
            -e CONFIG_GDB_SCRIPTS \
            -e CONFIG_KALLSYMS \
            -e CONFIG_KALLSYMS_ALL \
            -e CONFIG_MODULES \
            -e CONFIG_MODULE_UNLOAD \
            -e CONFIG_DEVTMPFS \
            -e CONFIG_DEVTMPFS_MOUNT \
            -e CONFIG_NET_9P \
            -e CONFIG_NET_9P_VIRTIO \
            -e CONFIG_9P_FS \
            -e CONFIG_9P_FS_POSIX_ACL \
            -e CONFIG_VIRTIO_PCI \
            -e CONFIG_VIRTIO_NET
        make olddefconfig
    fi

    echo "[*] Building kernel (j=$JOBS)..."
    make -j"$JOBS"

    # Copy bzImage to repo root
    cp arch/x86/boot/bzImage "$SCRIPT_DIR/bzImage"
    echo "[+] bzImage → $SCRIPT_DIR/bzImage"

    cd "$SCRIPT_DIR"
}

# ---- Build modules ----
build_modules() {
    echo ""
    echo "============================================"
    echo "  Building vulnerable kernel modules"
    echo "============================================"

    local kdir="$KERNEL_DIR"
    if [ ! -d "$kdir" ]; then
        echo "[!] Kernel source not found at $kdir"
        echo "    Run './build.sh' (full build) first, or set KDIR."
        exit 1
    fi

    local challenges=(
        "ch01-echo-chamber:vuln_echo"
        "ch02-echo-chamber-v2:vuln_echo2"
        "ch03-object-store:vuln_objstore"
        "ch04-secure-alloc:vuln_secalloc"
        "ch05-concurrent-log:vuln_conclog"
    )

    for entry in "${challenges[@]}"; do
        local ch="${entry%%:*}"
        local mod="${entry##*:}"
        echo "[*] Building $mod.ko for $ch..."
        make -C "$kdir" M="$SCRIPT_DIR/src/$ch" modules
        cp "$SCRIPT_DIR/src/$ch/$mod.ko" "$SCRIPT_DIR/challenges/$ch/"
        echo "[+] $mod.ko → challenges/$ch/"
    done
}

# ---- Build initramfs ----
build_initramfs() {
    echo ""
    echo "============================================"
    echo "  Building initramfs images"
    echo "============================================"

    "$SCRIPT_DIR/scripts/create_initramfs.sh" ch01-echo-chamber    vuln_echo.ko     "$FLAG_CH01" "$KERNEL_DIR"
    "$SCRIPT_DIR/scripts/create_initramfs.sh" ch02-echo-chamber-v2 vuln_echo2.ko    "$FLAG_CH02" "$KERNEL_DIR"
    "$SCRIPT_DIR/scripts/create_initramfs.sh" ch03-object-store    vuln_objstore.ko "$FLAG_CH03" "$KERNEL_DIR"
    "$SCRIPT_DIR/scripts/create_initramfs.sh" ch04-secure-alloc    vuln_secalloc.ko "$FLAG_CH04" "$KERNEL_DIR"
    "$SCRIPT_DIR/scripts/create_initramfs.sh" ch05-concurrent-log  vuln_conclog.ko  "$FLAG_CH05" "$KERNEL_DIR"

    echo ""
    echo "[+] All initramfs images created."
}

# ---- Package release tarball ----
package_release() {
    echo ""
    echo "============================================"
    echo "  Packaging release tarball"
    echo "============================================"

    local tarball="kernel-ctf-binaries-v1.0.tar.gz"

    tar czf "$tarball" \
        bzImage \
        challenges/ch01-echo-chamber/vuln_echo.ko \
        challenges/ch01-echo-chamber/initramfs.cpio.gz \
        challenges/ch02-echo-chamber-v2/vuln_echo2.ko \
        challenges/ch02-echo-chamber-v2/initramfs.cpio.gz \
        challenges/ch03-object-store/vuln_objstore.ko \
        challenges/ch03-object-store/initramfs.cpio.gz \
        challenges/ch04-secure-alloc/vuln_secalloc.ko \
        challenges/ch04-secure-alloc/initramfs.cpio.gz \
        challenges/ch05-concurrent-log/vuln_conclog.ko \
        challenges/ch05-concurrent-log/initramfs.cpio.gz

    echo "[+] Release tarball: $tarball ($(du -h "$tarball" | cut -f1))"
    echo ""
    echo "Upload this to GitHub Releases:"
    echo "  gh release upload v1.0 $tarball --clobber"
}

# ---- Main ----
MODE="${1:-full}"

case "$MODE" in
    full)
        check_deps
        build_kernel
        build_modules
        build_initramfs
        package_release
        ;;
    modules)
        check_deps
        build_modules
        build_initramfs
        ;;
    initramfs)
        build_initramfs
        ;;
    package)
        package_release
        ;;
    *)
        echo "Usage: $0 [full|modules|initramfs|package]"
        exit 1
        ;;
esac

echo ""
echo "============================================"
echo "  Build complete!"
echo "============================================"
echo ""
echo "Quick start:"
echo "  cd challenges/ch01-echo-chamber && ./run.sh 0"
echo ""
