#!/bin/bash
#
# create_initramfs.sh — Build initramfs.cpio.gz for a challenge
#
# Usage: ./scripts/create_initramfs.sh <challenge_name> <ko_file> <flag_text> [kernel_dir]
#
# Example:
#   ./scripts/create_initramfs.sh ch01-stacksmasher vuln_stack.ko "FLAG{...}" ./linux-6.1.75
#
set -e

CHALLENGE="${1:?Usage: $0 <challenge_name> <ko_file> <flag_text> [kernel_dir]}"
KO_FILE="${2:?Usage: $0 <challenge_name> <ko_file> <flag_text> [kernel_dir]}"
FLAG="${3:?Usage: $0 <challenge_name> <ko_file> <flag_text> [kernel_dir]}"
KDIR="${4:-}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CHALLENGE_DIR="$REPO_ROOT/challenges/$CHALLENGE"
KO_PATH="$CHALLENGE_DIR/$KO_FILE"
OUTPUT="$CHALLENGE_DIR/initramfs.cpio.gz"

BUSYBOX="$(which busybox 2>/dev/null || which busybox-static 2>/dev/null || true)"
if [ -z "$BUSYBOX" ]; then
    echo "[!] busybox or busybox-static not found. Install: sudo apt install busybox-static"
    exit 1
fi

if [ ! -f "$KO_PATH" ]; then
    echo "[!] Kernel module not found: $KO_PATH"
    exit 1
fi

MODULE_NAME="$(basename "$KO_FILE" .ko)"
DEV_NAME=""
case "$CHALLENGE" in
    ch01-stacksmasher) DEV_NAME="hackme" ;;
    ch02-ghost-note)   DEV_NAME="vuln_uaf" ;;
    ch03-timewarp)     DEV_NAME="vuln_race" ;;
    ch04-neighbors)    DEV_NAME="vuln_heap" ;;
    ch05-overflow)     DEV_NAME="vuln_intovf" ;;
    *) DEV_NAME="$MODULE_NAME" ;;
esac

TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT

echo "[*] Building initramfs for $CHALLENGE..."

# Create directory structure
mkdir -p "$TMP"/{bin,sbin,etc,proc,sys,dev,tmp,root,home/ctf,lib/modules}

# Install busybox
cp "$BUSYBOX" "$TMP/bin/busybox"
chmod 755 "$TMP/bin/busybox"

# Create busybox symlinks
for cmd in sh ash bash cat ls cp mv rm mkdir rmdir mount umount \
           echo printf grep awk sed head tail wc id whoami \
           chmod chown chgrp ln find xargs sort uniq tr cut \
           ps kill sleep dmesg insmod lsmod modprobe \
           vi less more hexdump xxd od strings \
           ifconfig ip ping wget nc telnet \
           tar gzip gunzip dd df du free top \
           test [ expr true false; do
    ln -sf /bin/busybox "$TMP/bin/$cmd" 2>/dev/null || true
done
ln -sf /bin/busybox "$TMP/sbin/init" 2>/dev/null || true

# Copy the vulnerable kernel module
cp "$KO_PATH" "$TMP/lib/modules/$KO_FILE"

# Create flag
echo -n "$FLAG" > "$TMP/root/flag.txt"
chmod 400 "$TMP/root/flag.txt"

# Create /etc/passwd and /etc/group
cat > "$TMP/etc/passwd" << 'PASSWD'
root:x:0:0:root:/root:/bin/sh
ctf:x:1000:1000:CTF Player:/home/ctf:/bin/sh
PASSWD

cat > "$TMP/etc/group" << 'GROUP'
root:x:0:
ctf:x:1000:
GROUP

# Create init script
cat > "$TMP/init" << INITEOF
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts
mount -t devpts devpts /dev/pts

# Restrict dmesg to root only
echo 1 > /proc/sys/kernel/dmesg_restrict

# Load the vulnerable module
echo "[*] Loading $MODULE_NAME..."
insmod /lib/modules/$KO_FILE
if [ \$? -eq 0 ]; then
    echo "[+] Module loaded: /dev/$DEV_NAME"
else
    echo "[-] Failed to load module"
fi

# Set permissions
chown root:root /root/flag.txt
chmod 400 /root/flag.txt

echo ""
echo "=========================================="
echo "  kernel-ctf-lab :: $CHALLENGE"
echo "=========================================="
echo "  Device: /dev/$DEV_NAME"
echo "  Flag:   /root/flag.txt (root:400)"
echo "  User:   ctf (uid 1000)"
echo "=========================================="
echo ""

# Drop to unprivileged shell
setsid /bin/sh -c 'exec /bin/sh -l </dev/console >/dev/console 2>&1'

# Fallback
exec /bin/sh
INITEOF
chmod 755 "$TMP/init"

# Create .profile for ctf user
cat > "$TMP/home/ctf/.profile" << 'PROFILE'
export PS1='ctf@kernel-ctf:\w\$ '
export HOME=/home/ctf
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
cd /home/ctf
PROFILE
chown -R 1000:1000 "$TMP/home/ctf"

# Pack initramfs
echo "[*] Packing initramfs..."
(cd "$TMP" && find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -9 > "$OUTPUT")

echo "[+] Created: $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
