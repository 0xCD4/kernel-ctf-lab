/*
 * ch04-neighbors - vuln_heap.ko
 * Difficulty: 3/5
 *
 * Device: /dev/vuln_heap
 * Interface: ioctl() - 4 CRUD commands
 * Vulnerability: Heap buffer overflow (off-by-16)
 *
 * Objects are allocated on the kernel heap with kmalloc.
 * The EDIT operation allows writing 16 bytes past the end
 * of an object, corrupting adjacent heap objects.
 *
 * Exploitation path: overflow into adjacent object's data pointer,
 * then use that to get arbitrary write → overwrite modprobe_path.
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
MODULE_DESCRIPTION("ch04-neighbors: heap buffer overflow");

#define DEVICE_NAME "vuln_heap"

#define CMD_ALLOC  0xBEEF0001
#define CMD_FREE   0xBEEF0002
#define CMD_READ   0xBEEF0003
#define CMD_EDIT   0xBEEF0004

#define OBJ_DATA_SIZE 128
#define MAX_OBJS      32
#define OVERFLOW_EXTRA 16   /* "16 bytes too close" */

struct heap_obj {
    unsigned long id;
    unsigned long size;
    char data[OBJ_DATA_SIZE];
};

struct heap_io {
    unsigned long idx;
    unsigned long size;
    char __user *data;
};

static struct heap_obj *objects[MAX_OBJS];

static long vuln_heap_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    struct heap_io io;

    if (copy_from_user(&io, (void __user *)arg, sizeof(io)))
        return -EFAULT;

    if (io.idx >= MAX_OBJS)
        return -EINVAL;

    switch (cmd) {
    case CMD_ALLOC:
        if (objects[io.idx])
            return -EEXIST;
        objects[io.idx] = kmalloc(sizeof(struct heap_obj), GFP_KERNEL);
        if (!objects[io.idx])
            return -ENOMEM;
        memset(objects[io.idx], 0, sizeof(struct heap_obj));
        objects[io.idx]->id = io.idx;
        objects[io.idx]->size = OBJ_DATA_SIZE;
        break;

    case CMD_FREE:
        if (!objects[io.idx])
            return -ENOENT;
        kfree(objects[io.idx]);
        objects[io.idx] = NULL;
        break;

    case CMD_READ:
        if (!objects[io.idx])
            return -ENOENT;
        if (io.size > OBJ_DATA_SIZE)
            io.size = OBJ_DATA_SIZE;
        if (copy_to_user(io.data, objects[io.idx]->data, io.size))
            return -EFAULT;
        break;

    case CMD_EDIT:
        if (!objects[io.idx])
            return -ENOENT;

        /*
         * Bug: allows writing OBJ_DATA_SIZE + 16 bytes, but the
         * data buffer is only OBJ_DATA_SIZE. The extra 16 bytes
         * overflow into the adjacent kmalloc slab object.
         *
         * Exploitation: allocate two adjacent objects, overflow
         * from obj[N] into obj[N+1]'s header fields (id, size),
         * or into the next slab's metadata.
         *
         * With careful heap grooming, the overflow corrupts a
         * neighboring object's pointer, giving arbitrary r/w.
         * Target: overwrite modprobe_path to escalate privileges.
         */
        if (io.size > OBJ_DATA_SIZE + OVERFLOW_EXTRA)
            io.size = OBJ_DATA_SIZE + OVERFLOW_EXTRA;

        if (copy_from_user(objects[io.idx]->data, io.data, io.size))
            return -EFAULT;
        break;

    default:
        return -EINVAL;
    }

    return 0;
}

static int vuln_heap_open(struct inode *inode, struct file *f)
{
    return 0;
}

static int vuln_heap_release(struct inode *inode, struct file *f)
{
    return 0;
}

static const struct file_operations vuln_heap_fops = {
    .owner          = THIS_MODULE,
    .open           = vuln_heap_open,
    .release        = vuln_heap_release,
    .unlocked_ioctl = vuln_heap_ioctl,
};

static struct miscdevice vuln_heap_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = DEVICE_NAME,
    .fops  = &vuln_heap_fops,
    .mode  = 0666,
};

static int __init vuln_heap_init(void)
{
    int ret = misc_register(&vuln_heap_dev);
    if (ret)
        pr_err("vuln_heap: failed to register\n");
    else
        pr_info("vuln_heap: loaded\n");
    return ret;
}

static void __exit vuln_heap_exit(void)
{
    int i;
    for (i = 0; i < MAX_OBJS; i++) {
        kfree(objects[i]);
        objects[i] = NULL;
    }
    misc_deregister(&vuln_heap_dev);
    pr_info("vuln_heap: unloaded\n");
}

module_init(vuln_heap_init);
module_exit(vuln_heap_exit);
