# kernel-ctf-lab

> 5 vulnerable kernel modules. Source code included. Build, load, reverse, exploit, get root.

## Rules

- Each challenge has a **vulnerable kernel module** that runs inside a QEMU VM.
- You start as **uid 1000**. The flag is at `/root/flag.txt` (root:400).
- Source code is in `src/`. The real challenge is exploiting the compiled module without reading it first.
- Use whatever tools you want: Ghidra, IDA, GDB, pwntools, ropper -- anything goes.
- Start at **Level 0** (no mitigations). Once you get root, increase the level and do it again.

## Quick Start

```bash
git clone https://github.com/0xCD4/kernel-ctf-lab.git
cd kernel-ctf-lab

# download pre-built binaries from Releases
# https://github.com/0xCD4/kernel-ctf-lab/releases

sudo apt install -y qemu-system-x86 gdb gcc busybox-static

cd challenges/ch01-stacksmasher
./run.sh 0
```

## Kernel

You need a `bzImage` at the repo root. Grab it from releases or build one:

```bash
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.1.75.tar.xz
tar xf linux-6.1.75.tar.xz && cd linux-6.1.75
make defconfig
scripts/config -e CONFIG_DEBUG_INFO -e CONFIG_GDB_SCRIPTS \
               -e CONFIG_KALLSYMS -e CONFIG_KALLSYMS_ALL
make -j$(nproc)
cp arch/x86/boot/bzImage ../
```

Or run `./build.sh` to build everything from scratch.

## Challenges

### ch01-stacksmasher -- difficulty 1/5

- **Device:** `/dev/hackme`
- **Interface:** `read()` / `write()`
- **Source:** `src/ch01-stacksmasher/vuln_stack.c`
- **Hint:** Read more than you're given. Write more than you should.

<details>
<summary>Nudge (try without this first)</summary>

The driver has two operations. One gives you too much. The other takes too much. What sits between your local variables and the return address?
</details>

---

### ch02-ghost-note -- difficulty 2/5

- **Device:** `/dev/vuln_uaf`
- **Interface:** `ioctl()` -- 4 commands
- **Source:** `src/ch02-ghost-note/vuln_uaf.c`
- **Hint:** A ghost still haunts the room it died in. Who moves into a dead man's house?

<details>
<summary>Nudge</summary>

Create, destroy, read, edit. Destruction isn't complete -- something lingers. The kernel has popular residents that are exactly 1024 bytes and full of function pointers. Open enough doors and one will move in.
</details>

---

### ch03-timewarp -- difficulty 3/5

- **Device:** `/dev/vuln_race`
- **Interface:** `ioctl()` -- 2 commands
- **Source:** `src/ch03-timewarp/vuln_race.c`
- **Note:** Needs multi-core. Runs with `-smp 2` by default.
- **Hint:** The kernel reads your answer twice, but you can change it between glances.

<details>
<summary>Nudge</summary>

The driver validates your input, then reads it again to use it. What if the answer changes between the check and the use? Two threads, good timing. One command tells you where to look.
</details>

---

### ch04-neighbors -- difficulty 3/5

- **Device:** `/dev/vuln_heap`
- **Interface:** `ioctl()` -- 4 commands
- **Source:** `src/ch04-neighbors/vuln_heap.c`
- **Hint:** Your neighbor's fence is 16 bytes too close.

<details>
<summary>Nudge</summary>

Allocate objects on the heap. They sit next to each other. One operation lets you write a bit too far -- just enough to corrupt the neighbor. Once you control a pointer, there's a kernel string that decides what runs when the kernel meets an unknown binary format.
</details>

---

### ch05-overflow -- difficulty 4/5

- **Device:** `/dev/vuln_intovf`
- **Interface:** `ioctl()` -- 4 commands
- **Source:** `src/ch05-overflow/vuln_intovf.c`
- **Hint:** What happens when the sum of two large numbers becomes small?

<details>
<summary>Nudge</summary>

The driver allocates a buffer based on a size calculation. Size is a 32-bit number, and addition wraps around. A huge value plus another value equals a tiny value. Small allocation, huge write. The rest writes itself.
</details>

## Mitigation Levels

Each challenge supports 5 difficulty levels via `./run.sh <level>`:

| Level | SMEP | SMAP | KASLR | KPTI | What it means |
|-------|------|------|-------|------|---------------|
| 0 | off | off | off | off | No protection. ret2usr works directly. |
| 1 | on | off | off | off | Can't execute userspace code from ring 0. |
| 2 | on | off | on | off | Kernel base is randomized. Need a leak. |
| 3 | on | on | on | off | Can't access userspace memory from ring 0. |
| 4 | on | on | on | on | Page tables separated. Need a clean return. |

## GDB

Every challenge exposes a GDB stub on port 1234.

```bash
gdb ./linux-6.1.75/vmlinux
(gdb) target remote :1234
(gdb) c
```

Find module base address inside the VM:
```
cat /proc/modules | grep vuln
```

## Reversing the .ko Files

Kernel modules are ELF objects. Throw them into Ghidra or IDA. Look for:

- `init_module` -- registers the device
- `file_operations` struct -- function pointers for read/write/ioctl
- `copy_from_user` / `copy_to_user` -- data crossing the kernel boundary
- `kmalloc` / `kfree` -- heap allocations
- ioctl command constants
- struct layouts

```bash
file challenges/ch01-stacksmasher/vuln_stack.ko
readelf -s challenges/ch01-stacksmasher/vuln_stack.ko
```

## Loading Exploits

```bash
gcc -static -o exploit exploit.c -lpthread
./tools/inject_exploit.sh challenges/ch01-stacksmasher ./exploit
cd challenges/ch01-stacksmasher && ./run.sh 0
# inside the VM: /home/ctf/exploit
```

## Building From Source

```bash
sudo apt install -y gcc make flex bison bc libelf-dev libssl-dev \
                    busybox-static cpio wget qemu-system-x86

./build.sh            # full build: kernel + modules + initramfs
./build.sh modules    # modules only (needs kernel tree)
./build.sh initramfs  # initramfs only (needs compiled .ko files)
```

## Flag Verification

```bash
./tools/verify_flag.sh ch01 "FLAG{your_flag_here}"
```

Flags are verified against SHA-256 hashes. No plaintext answers in the repo.

---

0xcd4
