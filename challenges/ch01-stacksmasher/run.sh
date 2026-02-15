#!/bin/bash
# Usage: ./run.sh [level 0-4]
# Levels: 0=easy(nothing) 1=SMEP 2=+KASLR 3=+SMAP 4=all(+KPTI)
set -e
LEVEL="${1:-0}"
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

echo "[*] ch01-stacksmasher - Level $LEVEL - GDB :1234"
exec qemu-system-x86_64 \
    -m 256M -kernel "$KERNEL" -initrd ./initramfs.cpio.gz \
    -nographic $CPU -smp "$SMP" -append "$BOOT" \
    -no-reboot -monitor /dev/null -s
