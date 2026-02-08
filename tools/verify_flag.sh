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
HASHES[ch01]="ad1b048d435a1edd8e5929482ddcfd44232db5a25d0e2b51747c7bed2761e1ef"
HASHES[ch02]="771bd7110659e41137a9eb1bb568b1bda0774e7bac4eb654fcbc682be9d6d8b9"
HASHES[ch03]="5e01f9474238deb94f139f1f8808c2b6f1453485365d3828933e9ec32f76e410"
HASHES[ch04]="26bb10e615e13fd91c3593995de1d55b13affec8187e5d28e24a26d9654eeece"
HASHES[ch05]="d638d234ffd4f5ab0ad11d6f3d002197c878011c53813db28a2c8367525e4407"

if [ -z "${HASHES[$CH]}" ]; then
    echo "[-] Unknown challenge: $CH"
    echo "    Valid: ch01 ch02 ch03 ch04 ch05"
    exit 1
fi

# Hash the submitted flag
SUBMITTED=$(echo -n "$FLAG" | sha256sum | awk '{print $1}')

if [ "$SUBMITTED" = "${HASHES[$CH]}" ]; then
    echo ""
    echo "  [+] CORRECT! Challenge $CH solved."
    echo ""
else
    echo ""
    echo "  [-] Wrong flag for $CH. Keep digging."
    echo ""
fi
