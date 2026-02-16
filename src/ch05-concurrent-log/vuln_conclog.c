/*
 * vuln_conclog.c — Concurrent Log
 *
 * A multi-writer kernel logging device.  Each log entry is reference-
 * counted and freed when the last reader releases it.  The device is
 * designed for concurrent access (SMP=2).
 *
 * Bug:  The reference-count decrement in CMD_PUT is NOT atomic.  It
 *       reads refcount, checks > 0, then decrements and stores.  On
 *       SMP, two CPUs can race through the check simultaneously and
 *       both decrement, causing a double-free.
 *
 *       There is NO artificial delay (ndelay/udelay).  The race window
 *       is the natural gap between the read and the store of the
 *       refcount — the same pattern that causes real kernel bugs
 *       (cf. CVE-2016-4557, CVE-2022-29581, CVE-2023-3390).
 *
 * Intended exploitation path:
 *   1. Allocate a log entry (kmalloc-256)
 *   2. Race two threads on CMD_PUT → double-free
 *   3. Use userfaultfd or FUSE to widen the race window reliably
 *   4. Reclaim the first free with pipe_buffer (also kmalloc-256 via pipe())
 *   5. Second free corrupts the freelist → overlapping objects
 *   6. Leak kernel text via pipe_buffer->ops (→ anon_pipe_buf_ops)
 *   7. Build arbitrary read/write by corrupting pipe_buffer->page
 *   8. Overwrite current task's cred->uid to 0 (direct cred overwrite)
 *
 * This is intentionally a DIFFERENT exploitation path from CH04:
 *   - CH04 teaches modprobe_path (data target in .data section)
 *   - CH05 teaches cred overwrite (data target on the heap via task_struct)
 * Both are data-only, but the spray object (pipe_buffer vs msg_msg),
 * the leak source, and the write target are all different.
 *
 * Mitigations: Level 5 — ALL (SMEP + SMAP + KASLR + KPTI + canaries)
 *
 * Device: /dev/conclog
 * Interface: ioctl() — 4 commands
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#define DEVICE_NAME   "conclog"
#define MAX_ENTRIES   16
#define ENTRY_SIZE    192     /* data portion */

#define CMD_ALLOC     _IOW('L', 1, struct conclog_io)
#define CMD_READ      _IOR('L', 2, struct conclog_io)
#define CMD_WRITE     _IOW('L', 3, struct conclog_io)
#define CMD_PUT       _IOW('L', 4, struct conclog_io)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kernel-ctf-lab");
MODULE_DESCRIPTION("Concurrent Log — race condition → double free");

struct conclog_io {
    unsigned long idx;
    unsigned long size;
    char __user  *data;
};

/*
 * Log entry layout.  Total struct size lands in kmalloc-256.
 * The refcount field is intentionally a plain int (not atomic_t)
 * — this is the bug.
 */
struct log_entry {
    int           refcount;   /* BUG: non-atomic reference count */
    unsigned int  data_len;
    char          data[ENTRY_SIZE];
};

static struct log_entry *entries[MAX_ENTRIES];

/*
 * NOTE: we deliberately use a NON-exclusive lock (rwlock) for the
 * entry table, and no per-entry lock for the refcount path.
 * CMD_PUT only takes a read lock (not write lock) because it
 * "only reads" the pointer — the refcount update is unprotected.
 * This is the realistic pattern: developers assume the refcount
 * is "its own synchronisation" but forget atomicity.
 */
static DEFINE_RWLOCK(log_rwlock);

static long conclog_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    struct conclog_io io;
    long ret = 0;

    if (copy_from_user(&io, (void __user *)arg, sizeof(io)))
        return -EFAULT;

    if (io.idx >= MAX_ENTRIES)
        return -EINVAL;

    switch (cmd) {
    case CMD_ALLOC:
        write_lock(&log_rwlock);
        if (entries[io.idx]) {
            ret = -EEXIST;
        } else {
            entries[io.idx] = kmalloc(sizeof(struct log_entry), GFP_KERNEL);
            if (!entries[io.idx]) {
                ret = -ENOMEM;
            } else {
                memset(entries[io.idx], 0, sizeof(struct log_entry));
                entries[io.idx]->refcount = 1;
            }
        }
        write_unlock(&log_rwlock);
        break;

    case CMD_READ:
        read_lock(&log_rwlock);
        if (!entries[io.idx] || entries[io.idx]->refcount <= 0) {
            ret = -ENOENT;
        } else {
            if (io.size > entries[io.idx]->data_len)
                io.size = entries[io.idx]->data_len;
            if (io.size > 0 && copy_to_user(io.data, entries[io.idx]->data, io.size))
                ret = -EFAULT;
        }
        read_unlock(&log_rwlock);
        break;

    case CMD_WRITE:
        read_lock(&log_rwlock);
        if (!entries[io.idx] || entries[io.idx]->refcount <= 0) {
            ret = -ENOENT;
        } else {
            if (io.size > ENTRY_SIZE)
                io.size = ENTRY_SIZE;
            if (copy_from_user(entries[io.idx]->data, io.data, io.size))
                ret = -EFAULT;
            else
                entries[io.idx]->data_len = io.size;
        }
        read_unlock(&log_rwlock);
        break;

    case CMD_PUT:
        /*
         * Decrement refcount and free if it reaches zero.
         *
         * BUG: This path uses a read lock (shared), NOT a write
         * lock.  Multiple CPUs can enter simultaneously.  The
         * refcount check and decrement are NOT atomic:
         *
         *   CPU 0                      CPU 1
         *   ─────                      ─────
         *   read refcount (== 1)
         *                              read refcount (== 1)
         *   refcount > 0 → true
         *                              refcount > 0 → true
         *   refcount-- → 0
         *   kfree(entry)
         *                              refcount-- → -1
         *                              kfree(entry)  ← DOUBLE FREE
         *
         * The pointer is nullified after free, but the second
         * free has already happened by then.
         *
         * There is no artificial delay.  The window is small
         * but real — the student can widen it using userfaultfd
         * or FUSE to block one thread inside copy_from_user on
         * the CMD_WRITE path, then race CMD_PUT.
         *
         * Alternatively, rapid concurrent CMD_PUT calls from
         * two threads will hit the window with enough attempts
         * (typically < 1000 iterations on SMP=2).
         */
        read_lock(&log_rwlock);
        if (!entries[io.idx]) {
            ret = -ENOENT;
            read_unlock(&log_rwlock);
            break;
        }

        if (entries[io.idx]->refcount > 0) {
            entries[io.idx]->refcount--;

            if (entries[io.idx]->refcount == 0) {
                kfree(entries[io.idx]);
                entries[io.idx] = NULL;
            }
        } else {
            ret = -EINVAL;
        }
        read_unlock(&log_rwlock);
        break;

    default:
        ret = -ENOTTY;
    }

    return ret;
}

static int conclog_open(struct inode *i, struct file *f)
{
    return 0;
}

static int conclog_release(struct inode *i, struct file *f)
{
    return 0;
}

static const struct file_operations conclog_fops = {
    .owner          = THIS_MODULE,
    .open           = conclog_open,
    .release        = conclog_release,
    .unlocked_ioctl = conclog_ioctl,
};

static struct miscdevice conclog_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = DEVICE_NAME,
    .fops  = &conclog_fops,
    .mode  = 0666,
};

static int __init conclog_init(void)
{
    int ret = misc_register(&conclog_dev);
    if (ret)
        pr_err("conclog: failed to register device\n");
    else
        pr_info("conclog: /dev/%s registered (max_entries=%d, smp required)\n",
                DEVICE_NAME, MAX_ENTRIES);
    return ret;
}

static void __exit conclog_exit(void)
{
    int i;
    write_lock(&log_rwlock);
    for (i = 0; i < MAX_ENTRIES; i++) {
        kfree(entries[i]);
        entries[i] = NULL;
    }
    write_unlock(&log_rwlock);
    misc_deregister(&conclog_dev);
    pr_info("conclog: device unregistered\n");
}

module_init(conclog_init);
module_exit(conclog_exit);
