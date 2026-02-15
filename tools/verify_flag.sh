#!/bin/bash
#
# verify_flag.sh — Check if your flag is correct (without revealing answers)
#
# Usage: ./verify_flag.sh <challenge> <flag>
# Example: ./verify_flag.sh ch01 "FLAG{something_here}"
#
set -e

if [ $# -ne 2 ]; then
    echo "Usage: $0 <challenge> <flag>"
    echo ""
    echo "Challenges: ch01  ch02  ch03  ch04  ch05"
    echo "Example:    $0 ch01 'FLAG{your_flag_here}'"
    exit 1
fi

CH="$1"
FLAG="$2"

# SHA-256 hashes of correct flags (students can't reverse these)
declare -A HASHES
HASHES[ch01]="24a692e7c9dc0e465565d89bfffe9a4a668b75633d97dc54d8e455cab8979864"
HASHES[ch02]="7c8f97175f71e6b28f0076115fbda020275133ba5444db98c78b2987fd916c5a"
HASHES[ch03]="9a111564ac1ce4cfc158a42afb07081458b0092eed0282ae49156a0f4d533b67"
HASHES[ch04]="31b0b8ca2ede326ba3cf4607f6a0aee67d3986d5033621970b40f3cfcd1a1b1f"
HASHES[ch05]="ec845f917d979390598b18e6ddd963a65706e2b5971ff1db4b1ce14961805e68"

if [ -z "${HASHES[$CH]}" ]; then
    echo "[-] Unknown challenge: $CH"
    echo "    Valid: ch01 ch02 ch03 ch04 ch05"
    exit 1
fi

# Hash the submitted flag
SUBMITTED=$(echo -n "$FLAG" | sha256sum | awk '{print $1}')

if [ "$SUBMITTED" = "${HASHES[$CH]}" ]; then
    echo ""
    echo "  ✅  CORRECT! Challenge $CH solved."
    echo ""
else
    echo ""
    echo "  ❌  Wrong flag for $CH. Keep digging."
    echo ""
fi
