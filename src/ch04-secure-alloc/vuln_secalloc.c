/*
 * vuln_secalloc.c — Secure Allocator
 *
 * A "secure" kernel memory allocator that prepends a metadata header
 * to every allocation.  The driver advertises a safe maximum data size
 * and performs bounds checking — but the size arithmetic is done with
 * 32-bit unsigned integers, making it vulnerable to integer wrapping.
 *
 * Bug:  total = user_size + HEADER_SIZE  is computed as uint32_t.
 *       If user_size is close to UINT32_MAX, the addition wraps and
 *       total becomes small.  The kernel allocates a tiny buffer but
 *       records the original (huge) user_size in the header.  A
 *       subsequent write uses the stored size as the upper bound,
 *       causing a massive heap overflow.
 *
 * Intended exploitation path (data-only, no ROP):
 *   1. Trigger integer overflow → tiny alloc, huge data_size recorded
 *   2. Heap-groom with msg_msg structures in adjacent slots
 *   3. CMD_WRITE overflows into neighbouring msg_msg → corrupt m_ts/next
 *   4. Use corrupted msg_msg for arbitrary kernel read
 *   5. Overwrite modprobe_path → trigger unknown-binfmt → root
 *
 * This challenge intentionally does NOT require ROP.  Stack canaries
 * are enabled at this level, making stack-based ROP expensive.  The
 * data-only path through modprobe_path is the intended solve, teaching
 * students that modern kernel exploitation often avoids code reuse.
 *
 * Mitigations: Level 4 — SMEP + KASLR + SMAP + stack canaries.
 *
 * Device: /dev/secalloc
 * Interface: ioctl() — 4 commands
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#define DEVICE_NAME  "secalloc"
#define MAX_BUFS     8
#define HEADER_SIZE  64

#define CMD_CREATE   _IOW('S', 1, struct secalloc_io)
#define CMD_WRITE    _IOW('S', 2, struct secalloc_io)
#define CMD_READ     _IOR('S', 3, struct secalloc_io)
#define CMD_DESTROY  _IOW('S', 4, struct secalloc_io)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kernel-ctf-lab");
MODULE_DESCRIPTION("Secure Allocator — integer overflow → heap OOB");

struct secalloc_io {
    unsigned long idx;
    uint32_t      size;     /* 32-bit — wraps on overflow */
    char __user  *data;
};

/*
 * Buffer header — prepended to every allocation.
 * The driver stores both the allocated total and the user-requested
 * data size. The bug is that alloc_size can be tiny (after wrapping)
 * while data_size remains huge.
 */
struct buf_header {
    uint32_t magic;         /* 0x5ECA110C — "SECALLOC" */
    uint32_t alloc_size;    /* actual kmalloc size (may be tiny) */
    uint32_t data_size;     /* user-requested size (may be huge) */
    uint32_t flags;
    char     tag[16];       /* user-settable tag */
    char     reserved[32];
    /* data follows immediately at offset HEADER_SIZE */
};

static struct buf_header *buffers[MAX_BUFS];
static DEFINE_MUTEX(alloc_lock);

static long secalloc_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    struct secalloc_io io;
    long ret = 0;

    if (copy_from_user(&io, (void __user *)arg, sizeof(io)))
        return -EFAULT;

    if (io.idx >= MAX_BUFS)
        return -EINVAL;

    mutex_lock(&alloc_lock);

    switch (cmd) {
    case CMD_CREATE: {
        /*
         * BUG: 32-bit arithmetic overflow.
         *
         * total_size = io.size + HEADER_SIZE
         *
         * Example: io.size = 0xFFFFFFC0
         *   total_size = 0xFFFFFFC0 + 0x40 = 0x100000000
         *   → truncated to uint32_t → 0x00000000
         *
         * kmalloc(0) returns ZERO_SIZE_PTR or a tiny slab object.
         * But data_size stores the original 0xFFFFFFC0, allowing
         * a subsequent CMD_WRITE to overflow massively.
         *
         * This pattern mirrors CVE-2021-22555 style integer issues
         * and is common in drivers that compute allocation sizes
         * from user-controlled 32-bit fields.
         */
        uint32_t total_size;

        if (buffers[io.idx]) {
            ret = -EEXIST;
            break;
        }

        total_size = io.size + HEADER_SIZE;  /* 32-bit wrapping */

        /*
         * Sanity check: if total looks reasonable, use it.
         * If it wrapped to 0 or something huge, fall back to
         * a small "safe" allocation.  Either way, the driver
         * proceeds — it trusts its own arithmetic.
         */
        if (total_size == 0 || total_size > (1024 * 1024))
            total_size = 32;

        buffers[io.idx] = kmalloc(total_size, GFP_KERNEL);
        if (!buffers[io.idx]) {
            ret = -ENOMEM;
            break;
        }
        memset(buffers[io.idx], 0, total_size);
        buffers[io.idx]->magic      = 0x5ECA110C;
        buffers[io.idx]->alloc_size = total_size;
        buffers[io.idx]->data_size  = io.size;   /* stores ORIGINAL size */
        buffers[io.idx]->flags      = 0;
        break;
    }

    case CMD_WRITE: {
        /*
         * Write user data into the buffer's data region.
         *
         * The bound check uses header->data_size, which may be
         * the original huge value (e.g. 0xFFFFFFC0).  The actual
         * allocation may only be 32 bytes total.
         *
         * Result: copy_from_user writes far past the allocation
         * into adjacent slab objects → heap overflow.
         */
        char *data_start;
        uint32_t max_write;

        if (!buffers[io.idx]) {
            ret = -ENOENT;
            break;
        }

        data_start = (char *)buffers[io.idx] + HEADER_SIZE;
        max_write  = buffers[io.idx]->data_size;

        if (io.size > max_write)
            io.size = max_write;

        if (copy_from_user(data_start, io.data, io.size)) {
            ret = -EFAULT;
            break;
        }
        break;
    }

    case CMD_READ: {
        char *data_start;
        uint32_t max_read;

        if (!buffers[io.idx]) {
            ret = -ENOENT;
            break;
        }

        data_start = (char *)buffers[io.idx] + HEADER_SIZE;
        max_read   = buffers[io.idx]->data_size;

        if (io.size > max_read)
            io.size = max_read;

        if (copy_to_user(io.data, data_start, io.size)) {
            ret = -EFAULT;
            break;
        }
        break;
    }

    case CMD_DESTROY:
        if (!buffers[io.idx]) {
            ret = -ENOENT;
            break;
        }
        kfree(buffers[io.idx]);
        buffers[io.idx] = NULL;   /* properly cleaned up — no UAF here */
        break;

    default:
        ret = -ENOTTY;
    }

    mutex_unlock(&alloc_lock);
    return ret;
}

static int secalloc_open(struct inode *i, struct file *f)
{
    return 0;
}

static int secalloc_release(struct inode *i, struct file *f)
{
    return 0;
}

static const struct file_operations secalloc_fops = {
    .owner          = THIS_MODULE,
    .open           = secalloc_open,
    .release        = secalloc_release,
    .unlocked_ioctl = secalloc_ioctl,
};

static struct miscdevice secalloc_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = DEVICE_NAME,
    .fops  = &secalloc_fops,
    .mode  = 0666,
};

static int __init secalloc_init(void)
{
    int ret = misc_register(&secalloc_dev);
    if (ret)
        pr_err("secalloc: failed to register device\n");
    else
        pr_info("secalloc: /dev/%s registered (max_bufs=%d)\n",
                DEVICE_NAME, MAX_BUFS);
    return ret;
}

static void __exit secalloc_exit(void)
{
    int i;
    for (i = 0; i < MAX_BUFS; i++)
        kfree(buffers[i]);
    misc_deregister(&secalloc_dev);
    pr_info("secalloc: device unregistered\n");
}

module_init(secalloc_init);
module_exit(secalloc_exit);
