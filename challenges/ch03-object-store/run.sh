#!/bin/bash
# Usage: ./run.sh [level 0-4]
#
# CH03 — Object Store: UAF → tty_struct hijack → stack pivot → ROP
#
# Level 3: SMEP + KASLR + SMAP (intended solve level for this challenge)
#
# Shared folder: place exploits in ./shared/ and they appear at /shared in the VM
set -e
LEVEL="${1:-3}"
KERNEL="${KERNEL_PATH:-../../bzImage}"
[ ! -f "$KERNEL" ] && echo "[!] bzImage not found. Place it at lab root or set KERNEL_PATH." && exit 1

CPU="-cpu qemu64"; BOOT="console=ttyS0 quiet panic=1"; SMP=1
case "$LEVEL" in
    0) BOOT="$BOOT nokaslr nopti nosmep nosmap" ;;
    1) CPU="-cpu qemu64,+smep"; BOOT="$BOOT nokaslr nopti nosmap" ;;
    2) CPU="-cpu qemu64,+smep"; BOOT="$BOOT kaslr nopti nosmap" ;;
    3) CPU="-cpu qemu64,+smep,+smap"; BOOT="$BOOT kaslr nopti" ;;
    4) CPU="-cpu qemu64,+smep,+smap"; BOOT="$BOOT kaslr kpti=1"; SMP=2 ;;
    *) echo "Level 0-4 only"; exit 1 ;;
esac

mkdir -p ./shared

VIRTFS="-virtfs local,path=./shared,mount_tag=shared,security_model=mapped-xattr,id=shared0"

echo "[*] ch03-object-store - Level $LEVEL - GDB :1234"
echo "[*] Shared folder: ./shared → /shared inside VM"
exec qemu-system-x86_64 \
    -m 256M -kernel "$KERNEL" -initrd ./initramfs.cpio.gz \
    -nographic $CPU -smp "$SMP" -append "$BOOT" \
    $VIRTFS \
    -no-reboot -monitor /dev/null -s
