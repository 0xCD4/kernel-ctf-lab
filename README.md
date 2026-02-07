# 0xcd4 - Linux Kernel Exploitation CTF Lab

> 5 vulnerable kernel modules. No source code. Reverse. Analyze. Exploit. Root.

---

## Rules

- You receive **compiled `.ko` files only**. No source code.
- Each module is loaded inside a QEMU VM. You are `uid 1000`.
- **Goal**: Read `/root/flag.txt` (owned by root, mode 400).
- You may use **any tools**: Ghidra, IDA, Binary Ninja, GDB, pwndbg, pwntools, ROPgadget, ropper.
- Start at **Level 0** (all mitigations off). Once you pop root, crank up the level.

---

## Quick Start

```bash
# 1. Clone this repo
git clone https://github.com/0xCD4/kernel-ctf-lab.git
cd kernel-ctf-lab

# 2. Download challenge binaries from Releases
# https://github.com/0xCD4/kernel-ctf-lab/releases
# Extract into challenges/ directory

# 3. Install dependencies (Ubuntu 22.04 / 24.04)
sudo apt install -y qemu-system-x86 gdb gcc busybox-static

# 4. (Recommended) Install pwndbg
git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh && cd ..

# 5. Launch a challenge
cd challenges/ch01-stacksmasher/
./run.sh 0     # level 0 = no mitigations
```

---

## You Need a Kernel (bzImage)

Build one with debug symbols (helps with GDB + ROP gadget hunting):

```bash
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.1.75.tar.xz
tar xf linux-6.1.75.tar.xz && cd linux-6.1.75
make defconfig
scripts/config -e CONFIG_DEBUG_INFO -e CONFIG_GDB_SCRIPTS \
               -e CONFIG_KALLSYMS -e CONFIG_KALLSYMS_ALL
make -j$(nproc)
# Copy to lab root:
cp arch/x86/boot/bzImage /path/to/kernel-ctf-lab/
```

---

## GDB Attach

```bash
# In another terminal:
gdb /path/to/linux-6.1.75/vmlinux
(gdb) target remote :1234
(gdb) c
```

Module load address (inside VM): `cat /proc/modules | grep vuln`

---

## Challenges

### `ch01-stacksmasher` - difficulty: 1/5

|           |                                                              |
| --------- | ------------------------------------------------------------ |
| Device    | `/dev/hackme`                                                |
| Interface | `read()` / `write()`                                         |
| Hint      | *"Read more than you're given. Write more than you should."* |

<details>
<summary>Nudge (try without this first)</summary>

The driver has two operations. One gives you too much. The other takes too much. What lives between your local variables and the return address?
</details>

---

### `ch02-ghost-note` - difficulty: 2/5

|           |                                                                                  |
| --------- | -------------------------------------------------------------------------------- |
| Device    | `/dev/vuln_uaf`                                                                  |
| Interface | `ioctl()` - reverse the command numbers                                          |
| Hint      | *"A ghost still haunts the room it died in. Who moves into a dead man's house?"* |

<details>
<summary>Nudge</summary>

Four commands. One creates, one destroys, one reads, one edits. But destruction isn't complete, something lingers. The kernel has popular residents that are exactly 1024 bytes and full of function pointers. Open enough doors and one will move in.
</details>

---

### `ch03-timewarp` - difficulty: 3/5

|           |                                                                                |
| --------- | ------------------------------------------------------------------------------ |
| Device    | `/dev/vuln_race`                                                               |
| Interface | `ioctl()` - two commands                                                       |
| QEMU      | **Requires multi-core**: `./run.sh 4` or add `-smp 2`                          |
| Hint      | *"The kernel reads your answer twice, but you can change it between glances."* |

<details>
<summary>Nudge</summary>

The driver validates your input, then reads it again to use it. But what if the answer changes between the check and the use? You need two threads and very good timing. One command tells you where to look.
</details>

---

### `ch04-neighbors` - difficulty: 3/5

|           |                                                  |
| --------- | ------------------------------------------------ |
| Device    | `/dev/vuln_heap`                                 |
| Interface | `ioctl()` - four commands (CRUD)                 |
| Hint      | *"Your neighbor's fence is 16 bytes too close."* |

<details>
<summary>Nudge</summary>

Allocate objects. They live next to each other on the heap. One operation lets you write a little too far, just enough to corrupt the next object. Once you can write anywhere, there's a kernel string that controls what runs when the kernel encounters an unknown binary format.
</details>

---

### `ch05-overflow` - difficulty: 4/5

|           |                                                                   |
| --------- | ----------------------------------------------------------------- |
| Device    | `/dev/vuln_intovf`                                                |
| Interface | `ioctl()` - four commands                                         |
| Hint      | *"What happens when the sum of two large numbers becomes small?"* |

<details>
<summary>Nudge</summary>

The driver allocates a buffer based on a size calculation. But size is a 32-bit number, and addition can wrap around. A huge value plus another value equals... a tiny value. The kernel allocates a small buffer but thinks it's enormous. The rest writes itself.
</details>

---

## Mitigation Levels

```
Level 0:  Nothing          - ret2usr works, addresses known
Level 1:  SMEP             - can't execute userspace code from ring 0
Level 2:  SMEP + KASLR     - kernel base randomized, need info leak
Level 3:  SMEP+SMAP+KASLR  - can't access userspace data from ring 0
Level 4:  ALL + KPTI        - page tables separated, need clean return
```

| Level | SMEP | SMAP | KASLR | KPTI |
| ----- | ---- | ---- | ----- | ---- |
| 0     | -    | -    | -     | -    |
| 1     | +    | -    | -     | -    |
| 2     | +    | -    | +     | -    |
| 3     | +    | +    | +     | -    |
| 4     | +    | +    | +     | +    |

---

## Reverse Engineering the .ko

Kernel modules are ELF objects. Load them in Ghidra or IDA. Things to look for:

- **`init_module`** - entry point, usually calls `misc_register()`
- **`file_operations` struct** - contains pointers to `read`, `write`, `ioctl` handlers
- **`copy_from_user` / `copy_to_user`** - where user data enters/exits the kernel
- **`kmalloc` / `kfree`** - heap operations
- **ioctl command numbers** - constants in the switch statement
- **Struct layouts** - understand what the driver stores and how

```bash
# Quick info
file challenges/ch01-stacksmasher/vuln_stack.ko
readelf -s challenges/ch01-stacksmasher/vuln_stack.ko
modinfo challenges/ch01-stacksmasher/vuln_stack.ko
```

---

## Getting Exploits Into the VM

Use the `inject_exploit.sh` tool in `tools/`:

```bash
gcc -static -o exploit exploit.c -lpthread
./tools/inject_exploit.sh challenges/ch01-stacksmasher ./exploit
cd challenges/ch01-stacksmasher && ./run.sh 0
# Inside VM: /home/ctf/exploit
```

Or manually rebuild initramfs:

```bash
mkdir rootfs && cd rootfs
zcat ../initramfs.cpio.gz | cpio -idmv
cp /path/to/exploit ./home/ctf/
find . -print0 | cpio --null -o --format=newc | gzip -9 > ../initramfs.cpio.gz
```

---

## Flag Verification

Once you read `/root/flag.txt` inside the VM, verify your flag with the included tool:

```bash
./tools/verify_flag.sh ch01 "FLAG{your_flag_here}"
```

The script hashes your input with SHA-256 and compares it against the stored hash. It tells you if you got it right without revealing the actual answer. No network requests, everything runs locally.

```
  $ ./tools/verify_flag.sh ch01 "FLAG{wrong_flag}"
    [-] Wrong flag for ch01. Keep digging.

  $ ./tools/verify_flag.sh ch01 "FLAG{correct_flag}"
    [+] CORRECT! Challenge ch01 solved.
```

Valid challenge IDs: `ch01` `ch02` `ch03` `ch04` `ch05`

---

## Download Challenge Binaries

The `.ko` modules and `initramfs.cpio.gz` files are **not** in this repo. Download them from [**Releases**](https://github.com/0xCD4/kernel-ctf-lab/releases).

After downloading, extract inside this repo:

```bash
tar xzf kernel-ctf-binaries-v1.0.tar.gz -C challenges/
```

---

*0xcd4 - https://0xcd4.github.io*
