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
HASHES[ch01]="8550802487a235caf851b5bbcbd01b07b6e216397a34f655a7e69d2e4ee1e44a"
HASHES[ch02]="b3535dec2968fc4c0bd8f637e9a2618332760de1e371bcac3946a4f392aa8865"
HASHES[ch03]="d4a3d4034fd8bf1f5b65ee55eba7cddc1ca2504ff165d88e22f44b4be2b81b37"
HASHES[ch04]="0a4799f41eacd0225ea61f4f3632d0ddfe9ef1d2619725f734271cc796a0c09d"
HASHES[ch05]="d5728aa7737d32784ebeff5fe6143b07bf1e6e906e205a7601b6ad981cf113e8"

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
