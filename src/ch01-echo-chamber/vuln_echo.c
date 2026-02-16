/*
 * vuln_echo.c — Echo Chamber
 *
 * A simple kernel "echo" device. Write a message, read it back.
 *
 * Bug:  The write handler copies user data into a fixed-size stack buffer
 *       without checking that count fits. A large write overflows past the
 *       buffer and overwrites the saved return address.
 *
 * Mitigations: Level 0 — none. Direct ret2usr works.
 *
 * Device: /dev/echo
 * Interface: read() / write()
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#define DEVICE_NAME "echo"
#define BUF_SIZE    64

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kernel-ctf-lab");
MODULE_DESCRIPTION("Echo Chamber — stack buffer overflow");

/* Per-device state: last message written */
static char saved_msg[BUF_SIZE];
static size_t saved_len;

/*
 * echo_read — return the last saved message.
 *
 * No bug here. Straightforward bounded copy.
 */
static ssize_t echo_read(struct file *f, char __user *buf,
                         size_t count, loff_t *off)
{
    if (*off >= saved_len)
        return 0;
    if (count > saved_len - *off)
        count = saved_len - *off;
    if (copy_to_user(buf, saved_msg + *off, count))
        return -EFAULT;
    *off += count;
    return count;
}

/*
 * echo_write — store a message from the user.
 *
 * BUG: `count` comes directly from userspace and is passed straight
 *      to copy_from_user without checking against BUF_SIZE. Writing
 *      more than 64 bytes overflows `stack_buf` and corrupts the
 *      saved frame pointer and return address on the kernel stack.
 *
 *      This mirrors CVE-2016-6187 and similar missing-bounds-check
 *      vulnerabilities in real kernel drivers.
 */
static ssize_t echo_write(struct file *f, const char __user *buf,
                          size_t count, loff_t *off)
{
    char stack_buf[BUF_SIZE];

    /* BUG: no upper-bound check on count */
    if (copy_from_user(stack_buf, buf, count))
        return -EFAULT;

    /* Save for later reads */
    if (count > BUF_SIZE)
        count = BUF_SIZE;
    memcpy(saved_msg, stack_buf, count);
    saved_len = count;

    return count;
}

static int echo_open(struct inode *i, struct file *f)
{
    return 0;
}

static int echo_release(struct inode *i, struct file *f)
{
    return 0;
}

static const struct file_operations echo_fops = {
    .owner   = THIS_MODULE,
    .open    = echo_open,
    .release = echo_release,
    .read    = echo_read,
    .write   = echo_write,
};

static struct miscdevice echo_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = DEVICE_NAME,
    .fops  = &echo_fops,
    .mode  = 0666,
};

static int __init echo_init(void)
{
    int ret = misc_register(&echo_dev);
    if (ret)
        pr_err("echo: failed to register device\n");
    else
        pr_info("echo: /dev/%s registered\n", DEVICE_NAME);
    return ret;
}

static void __exit echo_exit(void)
{
    misc_deregister(&echo_dev);
    pr_info("echo: device unregistered\n");
}

module_init(echo_init);
module_exit(echo_exit);
