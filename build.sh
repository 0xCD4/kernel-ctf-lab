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

# Challenge flags (update these as needed)
FLAG_CH01='FLAG{st4ck_sm4sh3d_r3t2usr_ez}'
FLAG_CH02='FLAG{gh0st_n0t3_uaf_spr4y3d}'
FLAG_CH03='FLAG{t1m3w4rp_r4c3_c0nd1t10n}'
FLAG_CH04='FLAG{n31ghb0rs_h34p_0v3rfl0w}'
FLAG_CH05='FLAG{1nt_0v3rfl0w_wr4p4r0und}'

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
            -e CONFIG_DEVTMPFS_MOUNT
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
        "ch01-stacksmasher:vuln_stack"
        "ch02-ghost-note:vuln_uaf"
        "ch03-timewarp:vuln_race"
        "ch04-neighbors:vuln_heap"
        "ch05-overflow:vuln_intovf"
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

    "$SCRIPT_DIR/scripts/create_initramfs.sh" ch01-stacksmasher vuln_stack.ko "$FLAG_CH01" "$KERNEL_DIR"
    "$SCRIPT_DIR/scripts/create_initramfs.sh" ch02-ghost-note   vuln_uaf.ko   "$FLAG_CH02" "$KERNEL_DIR"
    "$SCRIPT_DIR/scripts/create_initramfs.sh" ch03-timewarp     vuln_race.ko  "$FLAG_CH03" "$KERNEL_DIR"
    "$SCRIPT_DIR/scripts/create_initramfs.sh" ch04-neighbors    vuln_heap.ko  "$FLAG_CH04" "$KERNEL_DIR"
    "$SCRIPT_DIR/scripts/create_initramfs.sh" ch05-overflow     vuln_intovf.ko "$FLAG_CH05" "$KERNEL_DIR"

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
        challenges/ch01-stacksmasher/vuln_stack.ko \
        challenges/ch01-stacksmasher/initramfs.cpio.gz \
        challenges/ch02-ghost-note/vuln_uaf.ko \
        challenges/ch02-ghost-note/initramfs.cpio.gz \
        challenges/ch03-timewarp/vuln_race.ko \
        challenges/ch03-timewarp/initramfs.cpio.gz \
        challenges/ch04-neighbors/vuln_heap.ko \
        challenges/ch04-neighbors/initramfs.cpio.gz \
        challenges/ch05-overflow/vuln_intovf.ko \
        challenges/ch05-overflow/initramfs.cpio.gz

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
echo "  cd challenges/ch01-stacksmasher && ./run.sh 0"
echo ""
