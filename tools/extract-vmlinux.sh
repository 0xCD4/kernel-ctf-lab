#!/bin/bash
#
# extract-vmlinux.sh - Extract raw vmlinux from bzImage
#
# Usage: ./extract-vmlinux.sh <bzImage> > vmlinux
#
# Useful for finding ROP gadgets with ROPgadget
#
set -e

BZIMAGE="${1:?Usage: $0 <bzImage>}"

if [ ! -f "$BZIMAGE" ]; then
    echo "[!] File not found: $BZIMAGE" >&2
    exit 1
fi

# Find compression offset
offset=$(binwalk -y "raw gzip" -y "raw lzma" -y "raw xz" -y "raw bzip2" \
         -y "raw lzop" -y "raw zstd" "$BZIMAGE" 2>/dev/null | \
         grep -oP '^\d+' | head -1)

if [ -z "$offset" ]; then
    echo "[!] Could not find compressed data offset." >&2
    exit 1
fi

# Try different decompression methods
for cmd in gunzip unlzma "xz -d" bunzip2 lzop unzstd; do
    if dd if="$BZIMAGE" bs=1 skip="$offset" 2>/dev/null | $cmd 2>/dev/null; then
        exit 0
    fi
done

# Fallback: scripts/extract-vmlinux from kernel source
echo "[!] Could not extract. Try kernel source's scripts/extract-vmlinux instead." >&2
exit 1
