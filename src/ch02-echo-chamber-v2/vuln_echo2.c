/*
 * vuln_echo2.c — Echo Chamber v2
 *
 * Same echo device concept as CH01, but with an additional info-leak
 * in the read path. Designed to be exploited when SMEP and KASLR are
 * enabled — the student must:
 *   1. Leak kernel pointers via the read handler (defeat KASLR).
 *   2. Build a kernel ROP chain (defeat SMEP — can't ret2usr anymore).
 *
 * Bug 1 (info leak):
 *   The read handler declares a stack buffer, partially fills it with
 *   the saved message, but copies `count` bytes to userspace even when
 *   count > saved_len. The uninitialised tail of the stack buffer
 *   contains stale kernel pointers (saved registers, return addresses).
 *
 * Bug 2 (stack overflow):
 *   Same as CH01 — write handler has no bounds check on count.
 *
 * Mitigations: Level 2 — SMEP + KASLR.
 *
 * Device: /dev/echo2
 * Interface: read() / write()
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>

#define DEVICE_NAME "echo2"
#define BUF_SIZE    64
#define LEAK_MAX    256

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kernel-ctf-lab");
MODULE_DESCRIPTION("Echo Chamber v2 — stack overflow + info leak");

static char saved_msg[BUF_SIZE];
static size_t saved_len;

/*
 * echo2_read — return the saved message, but leak stack data.
 *
 * BUG: `stack_buf` is only partially initialised (memcpy of saved_len
 * bytes). The remaining bytes contain whatever was on the kernel stack
 * — typically saved rbp, return addresses, and callee-saved registers.
 * The handler copies up to LEAK_MAX (256) bytes from this 64-byte
 * buffer, giving the user access to adjacent stack frames.
 *
 * This pattern occurs in real drivers where a local buffer is built on
 * the stack and returned without full zeroing (cf. CVE-2010-4073,
 * CVE-2017-7308, countless /proc and ioctl info-leak bugs).
 */
static ssize_t echo2_read(struct file *f, char __user *buf,
                          size_t count, loff_t *off)
{
    char stack_buf[BUF_SIZE];

    /* Only copy the saved portion — rest of stack_buf is uninitialised */
    memcpy(stack_buf, saved_msg, saved_len);

    if (count > LEAK_MAX)
        count = LEAK_MAX;

    /* BUG: copies up to 256 bytes from a 64-byte stack buffer */
    if (copy_to_user(buf, stack_buf, count))
        return -EFAULT;

    return count;
}

/*
 * echo2_write — same overflow as CH01.
 *
 * BUG: no upper-bound check on count. Overflows the 64-byte stack_buf,
 * corrupting saved rbp and return address. With SMEP enabled, the
 * student must pivot to a kernel ROP chain instead of ret2usr.
 */
static ssize_t echo2_write(struct file *f, const char __user *buf,
                           size_t count, loff_t *off)
{
    char stack_buf[BUF_SIZE];

    if (copy_from_user(stack_buf, buf, count))
        return -EFAULT;

    if (count > BUF_SIZE)
        count = BUF_SIZE;
    memcpy(saved_msg, stack_buf, count);
    saved_len = count;

    return count;
}

static int echo2_open(struct inode *i, struct file *f)
{
    return 0;
}

static int echo2_release(struct inode *i, struct file *f)
{
    return 0;
}

static const struct file_operations echo2_fops = {
    .owner   = THIS_MODULE,
    .open    = echo2_open,
    .release = echo2_release,
    .read    = echo2_read,
    .write   = echo2_write,
};

static struct miscdevice echo2_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = DEVICE_NAME,
    .fops  = &echo2_fops,
    .mode  = 0666,
};

static int __init echo2_init(void)
{
    int ret = misc_register(&echo2_dev);
    if (ret)
        pr_err("echo2: failed to register device\n");
    else
        pr_info("echo2: /dev/%s registered\n", DEVICE_NAME);
    return ret;
}

static void __exit echo2_exit(void)
{
    misc_deregister(&echo2_dev);
    pr_info("echo2: device unregistered\n");
}

module_init(echo2_init);
module_exit(echo2_exit);
