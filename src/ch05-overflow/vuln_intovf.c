/*
 * ch05-overflow - vuln_intovf.ko
 * Difficulty: 4/5
 *
 * Device: /dev/vuln_intovf
 * Interface: ioctl() - 4 commands
 * Vulnerability: Integer overflow in size calculation
 *
 * CREATE allocates a buffer based on (user_size + header_size).
 * When user_size is close to UINT32_MAX, the addition wraps around,
 * causing a tiny allocation. Subsequent WRITE uses the original
 * (huge) size, causing a massive heap overflow.
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
MODULE_DESCRIPTION("ch05-overflow: integer overflow in size calculation");

#define DEVICE_NAME "vuln_intovf"

#define CMD_CREATE  0xF00D0001
#define CMD_WRITE   0xF00D0002
#define CMD_READ    0xF00D0003
#define CMD_DESTROY 0xF00D0004

#define HEADER_SIZE 64
#define MAX_BUFS    8

struct buf_header {
    uint32_t magic;
    uint32_t alloc_size;   /* The total allocated size (truncated u32) */
    uint32_t data_size;    /* The user-requested data size (original) */
    uint32_t flags;
    char     tag[16];
    char     reserved[32];
    /* data follows immediately after header */
};

struct intovf_io {
    unsigned long idx;
    uint32_t      size;    /* 32-bit size — wraps on overflow */
    char __user  *data;
};

static struct buf_header *buffers[MAX_BUFS];

static long vuln_intovf_ioctl(struct file *f, unsigned int cmd,
                              unsigned long arg)
{
    struct intovf_io io;
    uint32_t total_size;

    if (copy_from_user(&io, (void __user *)arg, sizeof(io)))
        return -EFAULT;

    if (io.idx >= MAX_BUFS)
        return -EINVAL;

    switch (cmd) {
    case CMD_CREATE:
        if (buffers[io.idx])
            return -EEXIST;

        /*
         * Bug: 32-bit arithmetic overflow.
         *
         * total_size = io.size + HEADER_SIZE
         *
         * If io.size = 0xFFFFFFC0, then:
         *   total_size = 0xFFFFFFC0 + 0x40 = 0x100000000
         *   But uint32_t wraps → total_size = 0x00000000
         *   kmalloc(0) returns ZERO_SIZE_PTR or small buffer
         *
         * If io.size = 0xFFFFFFD0, then:
         *   total_size = 0xFFFFFFD0 + 0x40 = 0x100000010
         *   Wraps → total_size = 0x10 (16 bytes!)
         *
         * The driver stores the ORIGINAL io.size as data_size,
         * which is used in CMD_WRITE for copy_from_user length.
         * Result: tiny buffer, huge write → heap overflow.
         */
        total_size = io.size + HEADER_SIZE;

        /* "Sanity check" that's meaningless after overflow */
        if (total_size > 0 && total_size < (1024 * 1024)) {
            buffers[io.idx] = kmalloc(total_size, GFP_KERNEL);
        } else {
            /*
             * When total_size == 0 (exact wrap), allocate minimum.
             * Still exploitable because data_size is huge.
             */
            buffers[io.idx] = kmalloc(32, GFP_KERNEL);
        }

        if (!buffers[io.idx])
            return -ENOMEM;

        memset(buffers[io.idx], 0, min_t(uint32_t, total_size, 32));
        buffers[io.idx]->magic = 0xDEADBEEF;
        buffers[io.idx]->alloc_size = total_size;
        buffers[io.idx]->data_size = io.size;  /* original huge value */
        buffers[io.idx]->flags = 0;
        strncpy(buffers[io.idx]->tag, "intovf", sizeof(buffers[io.idx]->tag));
        break;

    case CMD_WRITE:
        if (!buffers[io.idx])
            return -ENOENT;

        {
            char *data_start = (char *)buffers[io.idx] + HEADER_SIZE;
            uint32_t max_write = buffers[io.idx]->data_size;

            if (io.size > max_write)
                io.size = max_write;

            /*
             * Bug: io.size can be up to data_size (the original
             * huge value), but the actual allocation was tiny.
             * This causes a massive heap buffer overflow.
             */
            if (copy_from_user(data_start, io.data, io.size))
                return -EFAULT;
        }
        break;

    case CMD_READ:
        if (!buffers[io.idx])
            return -ENOENT;

        {
            char *data_start = (char *)buffers[io.idx] + HEADER_SIZE;
            uint32_t max_read = buffers[io.idx]->data_size;

            if (io.size > max_read)
                io.size = max_read;

            /* Can also read out of bounds — info leak */
            if (copy_to_user(io.data, data_start, io.size))
                return -EFAULT;
        }
        break;

    case CMD_DESTROY:
        if (!buffers[io.idx])
            return -ENOENT;
        kfree(buffers[io.idx]);
        buffers[io.idx] = NULL;
        break;

    default:
        return -EINVAL;
    }

    return 0;
}

static int vuln_intovf_open(struct inode *inode, struct file *f)
{
    return 0;
}

static int vuln_intovf_release(struct inode *inode, struct file *f)
{
    return 0;
}

static const struct file_operations vuln_intovf_fops = {
    .owner          = THIS_MODULE,
    .open           = vuln_intovf_open,
    .release        = vuln_intovf_release,
    .unlocked_ioctl = vuln_intovf_ioctl,
};

static struct miscdevice vuln_intovf_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = DEVICE_NAME,
    .fops  = &vuln_intovf_fops,
    .mode  = 0666,
};

static int __init vuln_intovf_init(void)
{
    int ret = misc_register(&vuln_intovf_dev);
    if (ret)
        pr_err("vuln_intovf: failed to register\n");
    else
        pr_info("vuln_intovf: loaded\n");
    return ret;
}

static void __exit vuln_intovf_exit(void)
{
    int i;
    for (i = 0; i < MAX_BUFS; i++) {
        kfree(buffers[i]);
        buffers[i] = NULL;
    }
    misc_deregister(&vuln_intovf_dev);
    pr_info("vuln_intovf: unloaded\n");
}

module_init(vuln_intovf_init);
module_exit(vuln_intovf_exit);
