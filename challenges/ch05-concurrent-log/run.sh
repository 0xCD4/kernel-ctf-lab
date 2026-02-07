#!/bin/bash
# Usage: ./run.sh [level 0-4]
#
# CH05 — Concurrent Log: race condition → double free → full chain
#
# This challenge requires SMP. All levels use -smp 2.
#
# Level 4: ALL mitigations (intended solve level for this challenge)
#
# Shared folder: place exploits in ./shared/ and they appear at /shared in the VM
set -e
LEVEL="${1:-4}"
KERNEL="${KERNEL_PATH:-../../bzImage}"
[ ! -f "$KERNEL" ] && echo "[!] bzImage not found. Place it at lab root or set KERNEL_PATH." && exit 1

CPU="-cpu qemu64"; BOOT="console=ttyS0 quiet panic=1"; SMP=2
case "$LEVEL" in
    0) BOOT="$BOOT nokaslr nopti nosmep nosmap" ;;
    1) CPU="-cpu qemu64,+smep"; BOOT="$BOOT nokaslr nopti nosmap" ;;
    2) CPU="-cpu qemu64,+smep"; BOOT="$BOOT kaslr nopti nosmap" ;;
    3) CPU="-cpu qemu64,+smep,+smap"; BOOT="$BOOT kaslr nopti" ;;
    4) CPU="-cpu qemu64,+smep,+smap"; BOOT="$BOOT kaslr kpti=1" ;;
    *) echo "Level 0-4 only"; exit 1 ;;
esac

mkdir -p ./shared

VIRTFS="-virtfs local,path=./shared,mount_tag=shared,security_model=mapped-xattr,id=shared0"

echo "[*] ch05-concurrent-log - Level $LEVEL (SMP=2) - GDB :1234"
echo "[*] Shared folder: ./shared → /shared inside VM"
exec qemu-system-x86_64 \
    -m 256M -kernel "$KERNEL" -initrd ./initramfs.cpio.gz \
    -nographic $CPU -smp "$SMP" -append "$BOOT" \
    $VIRTFS \
    -no-reboot -monitor /dev/null -s
