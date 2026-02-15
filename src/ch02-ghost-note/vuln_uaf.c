/*
 * ch02-ghost-note - vuln_uaf.ko
 * Difficulty: 2/5
 *
 * Device: /dev/vuln_uaf
 * Interface: ioctl() - 4 commands
 * Vulnerability: Use-after-free
 *
 * Four operations: CREATE, DESTROY, READ, EDIT.
 * DESTROY frees the object but does NOT null the pointer (dangling).
 * Object size is 1024 bytes — same as tty_struct, allowing
 * heap spraying with tty_struct for function-pointer hijacking.
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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("0xCD4");
MODULE_DESCRIPTION("ch02-ghost-note: use-after-free");

#define DEVICE_NAME "vuln_uaf"

#define NOTE_SIZE 1024   /* Same size as tty_struct */

#define CMD_CREATE  0xCAFE0001
#define CMD_DESTROY 0xCAFE0002
#define CMD_READ    0xCAFE0003
#define CMD_EDIT    0xCAFE0004

struct note_io {
    unsigned long idx;
    unsigned long size;
    char __user *data;
};

#define MAX_NOTES 16

static char *notes[MAX_NOTES];

static long vuln_uaf_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    struct note_io io;

    if (copy_from_user(&io, (void __user *)arg, sizeof(io)))
        return -EFAULT;

    if (io.idx >= MAX_NOTES)
        return -EINVAL;

    switch (cmd) {
    case CMD_CREATE:
        if (notes[io.idx])
            return -EEXIST;
        notes[io.idx] = kmalloc(NOTE_SIZE, GFP_KERNEL);
        if (!notes[io.idx])
            return -ENOMEM;
        memset(notes[io.idx], 0, NOTE_SIZE);
        break;

    case CMD_DESTROY:
        if (!notes[io.idx])
            return -ENOENT;
        kfree(notes[io.idx]);
        /*
         * Bug: pointer is NOT set to NULL after free.
         * The dangling pointer allows use-after-free via
         * CMD_READ and CMD_EDIT.
         */
        break;

    case CMD_READ:
        if (!notes[io.idx])
            return -ENOENT;
        if (io.size > NOTE_SIZE)
            io.size = NOTE_SIZE;
        /*
         * Bug: reads from potentially freed memory.
         * After spraying tty_struct into the freed slot,
         * this leaks tty_operations pointers (KASLR bypass).
         */
        if (copy_to_user(io.data, notes[io.idx], io.size))
            return -EFAULT;
        break;

    case CMD_EDIT:
        if (!notes[io.idx])
            return -ENOENT;
        if (io.size > NOTE_SIZE)
            io.size = NOTE_SIZE;
        /*
         * Bug: writes to potentially freed memory.
         * After spraying tty_struct, this overwrites function
         * pointers for code execution.
         */
        if (copy_from_user(notes[io.idx], io.data, io.size))
            return -EFAULT;
        break;

    default:
        return -EINVAL;
    }

    return 0;
}

static int vuln_uaf_open(struct inode *inode, struct file *f)
{
    return 0;
}

static int vuln_uaf_release(struct inode *inode, struct file *f)
{
    return 0;
}

static const struct file_operations vuln_uaf_fops = {
    .owner          = THIS_MODULE,
    .open           = vuln_uaf_open,
    .release        = vuln_uaf_release,
    .unlocked_ioctl = vuln_uaf_ioctl,
};

static struct miscdevice vuln_uaf_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = DEVICE_NAME,
    .fops  = &vuln_uaf_fops,
    .mode  = 0666,
};

static int __init vuln_uaf_init(void)
{
    int ret = misc_register(&vuln_uaf_dev);
    if (ret)
        pr_err("vuln_uaf: failed to register\n");
    else
        pr_info("vuln_uaf: loaded\n");
    return ret;
}

static void __exit vuln_uaf_exit(void)
{
    int i;
    for (i = 0; i < MAX_NOTES; i++)
        kfree(notes[i]);
    misc_deregister(&vuln_uaf_dev);
    pr_info("vuln_uaf: unloaded\n");
}

module_init(vuln_uaf_init);
module_exit(vuln_uaf_exit);
