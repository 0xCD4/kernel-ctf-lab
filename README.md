# kernel-ctf-lab

> 5 vulnerable kernel modules. Progressive mitigations. Realistic bugs. Get root.

## Rules

- Each challenge has a **vulnerable kernel module** that runs inside a QEMU VM.
- You start as **uid 1000**. The flag is at `/root/flag.txt` (root:400).
- Full source code is in `src/`. Read it, reverse the `.ko`, or both -- your call.
- Use whatever tools you want: Ghidra, IDA, GDB, pwntools, ropper -- anything goes.
- Each challenge has a **recommended level** where its intended technique applies. You can also run any challenge at any level for extra practice.
- Each challenge builds on the previous one. ROP (CH02) is reused in CH03 (stack pivot), then the data-only approach (CH04) shows you don't always need it. CH05 ties everything together.

## Quick Start

```bash
git clone https://github.com/0xCD4/kernel-ctf-lab.git
cd kernel-ctf-lab

# download pre-built binaries from Releases
# https://github.com/0xCD4/kernel-ctf-lab/releases

sudo apt install -y qemu-system-x86 gdb gcc busybox-static

cd challenges/ch01-echo-chamber
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

## Challenge Progression

The challenges are designed as a coherent curriculum. Each one introduces exactly one new exploitation concept while building on everything learned before.

```
CH01  →  CH02  →  CH03  →  CH04  →  CH05
 │        │        │        │        │
 │        │        │        │        └─ + race conditions, + KPTI bypass
 │        │        │        └─ + integer bugs, + data-only attacks, + canaries
 │        │        └─ + heap exploitation, + SMAP bypass (stack pivot)
 │        └─ + kernel ROP, + KASLR bypass, + SMEP
 └─ ret2usr fundamentals
```

### Why is kernel ROP introduced early?

This lab teaches two exploit styles:

- CH01-CH03: control flow attacks (stack overflow, kernel ROP, stack pivot with SMAP).
- CH04-CH05: data-only attacks (integer/race bugs, heap corruption, privilege gain without ROP).

CH02 comes early on purpose. You learn safe return to user mode once, then use the same idea again in later levels.

## Learning tracks (optional)

If you want a simpler path, use one of these tracks:

### Track A - Control flow

1. **CH01**: ret2usr basics
2. **CH02**: kernel ROP and KASLR leak
3. **CH03**: heap UAF, stack pivot, SMAP limits

### Track B - Data only

1. **CH04**: integer overflow to heap OOB and `modprobe_path`
2. **CH05**: refcount race, double free, direct `cred` overwrite

The normal order still works. These tracks are only an easier way to practice.

## Challenges

### ch01-echo-chamber -- ret2usr fundamentals

- **Device:** `/dev/echo`
- **Interface:** `read()` / `write()`
- **Source:** `src/ch01-echo-chamber/vuln_echo.c`
- **Level:** 0 (no mitigations)
- **New concept:** Basic kernel exploitation - stack layout, `commit_creds(prepare_kernel_cred(0))`, ret2usr

<details>
<summary>Hint</summary>

The driver stores your message on the stack. What happens when your message is larger than the buffer? Look at what sits between local variables and the return address. `/proc/kallsyms` tells you where everything lives.
</details>

---

### ch02-echo-chamber-v2 -- kernel ROP

- **Device:** `/dev/echo2`
- **Interface:** `read()` / `write()`
- **Source:** `src/ch02-echo-chamber-v2/vuln_echo2.c`
- **Level:** 2 (SMEP + KASLR)
- **New concept:** SMEP bypass via ROP chain, KASLR bypass via info leak, gadget hunting

<details>
<summary>Hint</summary>

Same overflow as CH01, but ret2usr no longer works - SMEP prevents the CPU from executing userspace code in ring 0. The read handler gives you more bytes than the buffer contains. What's in those extra bytes? Once you know the kernel base, build a chain: `prepare_kernel_cred` → `commit_creds` → `swapgs_restore_regs_and_return_to_usermode`.
</details>

---

### ch03-object-store -- heap exploitation (UAF)

- **Device:** `/dev/objstore`
- **Interface:** `ioctl()` -- 4 commands (create / read / write / delete)
- **Source:** `src/ch03-object-store/vuln_objstore.c`
- **Level:** 3 (SMEP + KASLR + SMAP)
- **New concept:** Use-after-free, heap spray with `tty_struct`, stack pivot, SMAP bypass
- **Design note:** This interface uses one ioctl copy for metadata and one copy for payload data. Many real drivers do this.

<details>
<summary>Hint</summary>

Create an object, delete it, then read through the stale pointer. Objects are 1024 bytes - the same slab as `tty_struct`. Open `/dev/ptmx` repeatedly to spray tty structures into the freed slot. The `tty_operations` pointer leaks the kernel base. Overwrite it to redirect a tty operation to a stack-pivot gadget. SMAP blocks direct userspace memory access - your ROP chain must live in kernel memory.
</details>

---

### ch04-secure-alloc -- data-only exploitation

- **Device:** `/dev/secalloc`
- **Interface:** `ioctl()` -- 4 commands (create / write / read / destroy)
- **Source:** `src/ch04-secure-alloc/vuln_secalloc.c`
- **Level:** 4 (SMEP + KASLR + SMAP + stack canaries)
- **New concept:** Integer overflow in size arithmetic, heap OOB via `msg_msg`, `modprobe_path` overwrite - **no ROP required**

<details>
<summary>Hint</summary>

The driver adds a 64-byte header to your requested size using 32-bit arithmetic. What happens when the sum wraps past `0xFFFFFFFF`? A tiny allocation with a huge recorded data size. Use `msgsnd`/`msgrcv` to groom the heap with `msg_msg` structures. Corrupt an adjacent `msg_msg` to build an arbitrary read. Find and overwrite `modprobe_path` - then trigger it with an unknown binary format. Stack canaries make ROP expensive; this challenge rewards a data-only approach.
</details>

---

### ch05-concurrent-log -- race conditions

- **Device:** `/dev/conclog`
- **Interface:** `ioctl()` -- 4 commands (alloc / read / write / put)
- **Source:** `src/ch05-concurrent-log/vuln_conclog.c`
- **Note:** Requires multi-core. All levels run with `-smp 2`.
- **Level:** 4 (all mitigations)
- **New concept:** Non-atomic refcount → double free, `userfaultfd`/FUSE for race stabilization, `pipe_buffer` spray, direct cred overwrite

<details>
<summary>Hint</summary>

The reference count is a plain `int`, not `atomic_t`. The decrement path uses a shared (read) lock - two CPUs can enter simultaneously. Race two threads on the put command: both read refcount=1, both decrement, both free. Use `userfaultfd` to widen the window. After the double free, spray with `pipe_buffer` structs (also kmalloc-256 -- use `pipe()` + `write()`). The `pipe_buffer->ops` pointer leaks the kernel base. Corrupt `pipe_buffer->page` for arbitrary read/write, then walk the task list to find your cred struct and zero out uid/gid. This is different from CH04: there you targeted `modprobe_path` (a global); here you target your process's `cred` struct (on the heap).
</details>

## Mitigation Levels

Each challenge supports 5 difficulty levels via `./run.sh <level>`. Challenges default to their intended level but you can override.

| Level | SMEP | SMAP | KASLR | KPTI | What you need |
|-------|------|------|-------|------|---------------|
| 0 | off | off | off | off | ret2usr works directly. |
| 1 | on | off | off | off | Can't execute userspace code from ring 0. Need ROP. |
| 2 | on | off | on | off | Kernel base is randomized. Need an info leak. |
| 3 | on | on | on | off | Can't access userspace memory from ring 0. Need stack pivot. |
| 4 | on | on | on | on | Page tables separated. Need a clean return to userspace. |

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
file challenges/ch01-echo-chamber/vuln_echo.ko
readelf -s challenges/ch01-echo-chamber/vuln_echo.ko
```

## Returning to Userspace

After `commit_creds(prepare_kernel_cred(0))` succeeds, you need to get back to userspace cleanly. How you do this depends on the active mitigations.

**Without KPTI (levels 0-3):**

```
swapgs
iretq    ← push: SS, RSP, RFLAGS, CS, RIP (in that order) before the chain
```

Save your user-mode registers (`cs`, `ss`, `rsp`, `rflags`, `rip`) **before** entering the kernel. Your ROP chain ends with `swapgs; iretq` which pops these five values off the stack and lands you back in your userspace function (typically one that calls `system("/bin/sh")`).

**With KPTI (level 4):**

KPTI separates kernel and user page tables. A plain `swapgs; iretq` will fault because the kernel pages disappear on return. The kernel provides a trampoline:

```
swapgs_restore_regs_and_return_to_usermode
```

Find it with `grep swapgs_restore_regs /proc/kallsyms`. Your ROP chain should jump into this function (skip the first few instructions that push registers - land at the `mov rdi, rsp` point). It handles the page table switch and `iretq` for you.

Find the exact offset with GDB:
```
(gdb) disas swapgs_restore_regs_and_return_to_usermode
```

## Loading Exploits

**Option 1: Shared folder (recommended)** -- no rebuild needed:

```bash
gcc -static -o exploit exploit.c -lpthread
cp exploit challenges/ch01-echo-chamber/shared/
cd challenges/ch01-echo-chamber && ./run.sh 0
# inside the VM: /shared/exploit
```

All `run.sh` scripts already enable virtio-9p and mount `/shared` in init. You can test new exploits without rebuilding initramfs each time.

**Option 2: Inject into initramfs:**

```bash
gcc -static -o exploit exploit.c -lpthread
./tools/inject_exploit.sh challenges/ch01-echo-chamber ./exploit
cd challenges/ch01-echo-chamber && ./run.sh 0
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

## Notes on realism and variety

- CH04 and CH05 can look similar because both can end in data-only privilege escalation. But they use different bug types and different targets (`msg_msg` + global target vs race + `pipe_buffer` + heap `cred` target).
- Future updates can add harder heap grooming ideas, like stronger refcount patterns and less direct dangling pointers.

## Flag Verification

```bash
./tools/verify_flag.sh ch01 "FLAG{your_flag_here}"
```

Flags are verified against SHA-256 hashes. No plaintext answers in the repo.

---

0xcd4
