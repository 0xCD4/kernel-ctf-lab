/*
 * ch01-stacksmasher - vuln_stack.ko
 * Difficulty: 1/5
 *
 * Device: /dev/hackme
 * Interface: read() / write()
 * Vulnerability: Stack buffer overflow
 *
 * BUILD ONLY - this file is NOT distributed to students.
 * Students receive the compiled .ko only.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("0xCD4");
MODULE_DESCRIPTION("ch01-stacksmasher: stack buffer overflow");

#define DEVICE_NAME "hackme"
#define SAFE_SIZE 64

/*
 * Vulnerability 1 (read): Info leak - copies more data than the
 * buffer contains, leaking stack contents (kernel pointers).
 *
 * Vulnerability 2 (write): Stack buffer overflow - copies user data
 * into a 64-byte stack buffer without proper size checking.
 */

static ssize_t hackme_read(struct file *f, char __user *buf,
                           size_t count, loff_t *off)
{
    char stack_buf[SAFE_SIZE];
    /* Initialize only the "safe" portion */
    memset(stack_buf, 0x41, SAFE_SIZE);

    /*
     * Bug: copies up to 256 bytes from stack, but buffer is only 64.
     * The extra bytes leak return addresses and saved registers.
     */
    if (count > 256)
        count = 256;

    if (copy_to_user(buf, stack_buf, count))
        return -EFAULT;

    return count;
}

static ssize_t hackme_write(struct file *f, const char __user *buf,
                            size_t count, loff_t *off)
{
    char stack_buf[SAFE_SIZE];

    /*
     * Bug: no upper bound on count. User can write far beyond the
     * 64-byte stack buffer, smashing the saved frame pointer and
     * return address.
     */
    if (copy_from_user(stack_buf, buf, count))
        return -EFAULT;

    return count;
}

static int hackme_open(struct inode *inode, struct file *f)
{
    return 0;
}

static int hackme_release(struct inode *inode, struct file *f)
{
    return 0;
}

static const struct file_operations hackme_fops = {
    .owner   = THIS_MODULE,
    .open    = hackme_open,
    .release = hackme_release,
    .read    = hackme_read,
    .write   = hackme_write,
};

static struct miscdevice hackme_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = DEVICE_NAME,
    .fops  = &hackme_fops,
    .mode  = 0666,
};

static int __init hackme_init(void)
{
    int ret = misc_register(&hackme_dev);
    if (ret)
        pr_err("hackme: failed to register device\n");
    else
        pr_info("hackme: device registered at /dev/%s\n", DEVICE_NAME);
    return ret;
}

static void __exit hackme_exit(void)
{
    misc_deregister(&hackme_dev);
    pr_info("hackme: device unregistered\n");
}

module_init(hackme_init);
module_exit(hackme_exit);
