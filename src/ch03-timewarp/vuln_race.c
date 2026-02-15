/*
 * ch03-timewarp - vuln_race.ko
 * Difficulty: 3/5
 *
 * Device: /dev/vuln_race
 * Interface: ioctl() - 2 commands
 * Vulnerability: TOCTOU race condition
 *
 * CMD_VALIDATE checks user-supplied data, then re-reads it from
 * userspace to use it. A second thread can modify the data between
 * the check and the use, bypassing validation.
 *
 * CMD_LEAK provides kernel text address for KASLR bypass.
 *
 * Requires SMP (-smp 2+) for reliable exploitation.
 *
 * BUILD ONLY - this file is NOT distributed to students.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/ioctl.h>
#include <linux/delay.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("0xCD4");
MODULE_DESCRIPTION("ch03-timewarp: TOCTOU race condition");

#define DEVICE_NAME "vuln_race"

#define CMD_VALIDATE 0xDEAD0001
#define CMD_LEAK     0xDEAD0002

#define SAFE_LIMIT 128

struct race_io {
    unsigned long size;
    char __user *data;
};

/*
 * Kernel buffer that can be overwritten via the race.
 * Placed near function pointers to enable control flow hijacking.
 */
static char kernel_buf[SAFE_LIMIT];

/* Simulated "secret" function that the exploit should redirect to */
static void win_function(void)
{
    /* In a real CTF this would escalate privileges */
    pr_info("vuln_race: privilege escalation triggered!\n");
}

static long vuln_race_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    struct race_io io;
    unsigned long user_size;

    switch (cmd) {
    case CMD_VALIDATE:
        if (copy_from_user(&io, (void __user *)arg, sizeof(io)))
            return -EFAULT;

        /*
         * Step 1: READ the size value from userspace for validation.
         */
        if (get_user(user_size, &((struct race_io __user *)arg)->size))
            return -EFAULT;

        /* Validate: size must be within safe limits */
        if (user_size > SAFE_LIMIT)
            return -EINVAL;

        /*
         * Bug: small delay + re-read from userspace.
         * A racing thread can change io.size between the check
         * above and the copy_from_user below, causing a buffer
         * overflow into kernel_buf (and beyond).
         */
        ndelay(100);

        /*
         * Step 2: RE-READ from the SAME userspace address.
         * The attacker thread flips size to a large value between
         * step 1 and step 2.
         */
        if (copy_from_user(&io, (void __user *)arg, sizeof(io)))
            return -EFAULT;

        /* Uses the (now-corrupted) size without re-checking */
        if (io.size > 4096)
            io.size = 4096;

        if (copy_from_user(kernel_buf, io.data, io.size))
            return -EFAULT;

        break;

    case CMD_LEAK:
        /*
         * Returns address of a kernel function for KASLR defeat.
         * Students use this to calculate kernel base.
         */
        {
            unsigned long addr = (unsigned long)win_function;
            if (copy_to_user((void __user *)arg, &addr, sizeof(addr)))
                return -EFAULT;
        }
        break;

    default:
        return -EINVAL;
    }

    return 0;
}

static int vuln_race_open(struct inode *inode, struct file *f)
{
    return 0;
}

static int vuln_race_release(struct inode *inode, struct file *f)
{
    return 0;
}

static const struct file_operations vuln_race_fops = {
    .owner          = THIS_MODULE,
    .open           = vuln_race_open,
    .release        = vuln_race_release,
    .unlocked_ioctl = vuln_race_ioctl,
};

static struct miscdevice vuln_race_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = DEVICE_NAME,
    .fops  = &vuln_race_fops,
    .mode  = 0666,
};

static int __init vuln_race_init(void)
{
    int ret = misc_register(&vuln_race_dev);
    if (ret)
        pr_err("vuln_race: failed to register\n");
    else
        pr_info("vuln_race: loaded (needs -smp 2)\n");
    return ret;
}

static void __exit vuln_race_exit(void)
{
    misc_deregister(&vuln_race_dev);
    pr_info("vuln_race: unloaded\n");
}

module_init(vuln_race_init);
module_exit(vuln_race_exit);
