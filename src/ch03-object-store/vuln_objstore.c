/*
 * vuln_objstore.c — Object Store
 *
 * A kernel object-management device supporting create / read / write /
 * delete operations via ioctl. Objects are heap-allocated from the
 * kmalloc-1024 slab, the same cache used by tty_struct.
 *
 * Bug:  The delete handler calls kfree() on the object but does NOT
 *       null the slot pointer — a classic use-after-free through a
 *       dangling pointer.  Subsequent read/write operations through
 *       the stale pointer access whatever now occupies the freed slot.
 *
 * Intended exploitation path:
 *   1. Create object → kmalloc-1024
 *   2. Delete object → kfree, but pointer remains
 *   3. Spray tty_struct (also kmalloc-1024) to reclaim the slot
 *   4. Read through dangling pointer → leak tty_operations (KASLR bypass)
 *   5. Write through dangling pointer → overwrite tty_operations
 *   6. Stack pivot → kernel ROP chain (reuses CH02 knowledge)
 *
 * Mitigations: Level 3 — SMEP + KASLR + SMAP.
 *   SMAP means the exploit cannot directly reference userspace
 *   buffers from kernel context — stack pivot is required.
 *
 * Device: /dev/objstore
 * Interface: ioctl() — 4 commands
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#define DEVICE_NAME  "objstore"
#define MAX_OBJECTS  16
#define OBJ_SIZE     1024   /* matches kmalloc-1024, same as tty_struct */

#define CMD_CREATE   _IOW('O', 1, struct objstore_io)
#define CMD_READ     _IOR('O', 2, struct objstore_io)
#define CMD_WRITE    _IOW('O', 3, struct objstore_io)
#define CMD_DELETE    _IO('O',  4)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kernel-ctf-lab");
MODULE_DESCRIPTION("Object Store — use-after-free via dangling pointer");

struct objstore_io {
    unsigned long idx;
    unsigned long size;
    char __user  *data;
};

/*
 * Object layout — a simple data blob.  The entire 1024 bytes are
 * available to the user.  When a tty_struct lands in the same slot
 * after the UAF, the first 8 bytes overlap with tty->magic and
 * bytes 24-32 overlap with the tty_operations pointer.
 */
struct obj_entry {
    char data[OBJ_SIZE];
};

static struct obj_entry *objects[MAX_OBJECTS];
static DEFINE_MUTEX(store_lock);

static long objstore_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    struct objstore_io io;
    long ret = 0;

    if (cmd == CMD_DELETE) {
        /*
         * CMD_DELETE takes just an index via arg directly.
         * This keeps the ioctl interface minimal.
         */
        unsigned long idx = arg;
        mutex_lock(&store_lock);
        if (idx >= MAX_OBJECTS || !objects[idx]) {
            mutex_unlock(&store_lock);
            return -ENOENT;
        }
        kfree(objects[idx]);
        /*
         * BUG: pointer NOT set to NULL after free.
         *
         * This is the classic dangling-pointer pattern seen in real
         * kernel drivers (cf. CVE-2021-22555, CVE-2022-2588).
         * The slot still holds the old address, so subsequent
         * CMD_READ / CMD_WRITE access freed memory.
         */
        mutex_unlock(&store_lock);
        return 0;
    }

    if (copy_from_user(&io, (void __user *)arg, sizeof(io)))
        return -EFAULT;

    if (io.idx >= MAX_OBJECTS)
        return -EINVAL;

    mutex_lock(&store_lock);

    switch (cmd) {
    case CMD_CREATE:
        if (objects[io.idx]) {
            ret = -EEXIST;
            break;
        }
        objects[io.idx] = kmalloc(OBJ_SIZE, GFP_KERNEL);
        if (!objects[io.idx]) {
            ret = -ENOMEM;
            break;
        }
        memset(objects[io.idx], 0, OBJ_SIZE);
        break;

    case CMD_READ:
        if (!objects[io.idx]) {
            ret = -ENOENT;
            break;
        }
        if (io.size > OBJ_SIZE)
            io.size = OBJ_SIZE;
        /*
         * If the slot was freed and reclaimed by a tty_struct,
         * this leaks tty_struct contents including the
         * tty_operations pointer → KASLR defeat.
         */
        if (copy_to_user(io.data, objects[io.idx]->data, io.size)) {
            ret = -EFAULT;
            break;
        }
        break;

    case CMD_WRITE:
        if (!objects[io.idx]) {
            ret = -ENOENT;
            break;
        }
        if (io.size > OBJ_SIZE)
            io.size = OBJ_SIZE;
        /*
         * If the slot was freed and reclaimed by a tty_struct,
         * this overwrites tty_struct fields — including the
         * tty_operations function-pointer table. The attacker
         * can redirect any tty operation (e.g. ioctl, write)
         * to a stack-pivot gadget → kernel ROP.
         */
        if (copy_from_user(objects[io.idx]->data, io.data, io.size)) {
            ret = -EFAULT;
            break;
        }
        break;

    default:
        ret = -ENOTTY;
    }

    mutex_unlock(&store_lock);
    return ret;
}

static int objstore_open(struct inode *i, struct file *f)
{
    return 0;
}

static int objstore_release(struct inode *i, struct file *f)
{
    return 0;
}

static const struct file_operations objstore_fops = {
    .owner          = THIS_MODULE,
    .open           = objstore_open,
    .release        = objstore_release,
    .unlocked_ioctl = objstore_ioctl,
};

static struct miscdevice objstore_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = DEVICE_NAME,
    .fops  = &objstore_fops,
    .mode  = 0666,
};

static int __init objstore_init(void)
{
    int ret = misc_register(&objstore_dev);
    if (ret)
        pr_err("objstore: failed to register device\n");
    else
        pr_info("objstore: /dev/%s registered (obj_size=%d, max=%d)\n",
                DEVICE_NAME, OBJ_SIZE, MAX_OBJECTS);
    return ret;
}

static void __exit objstore_exit(void)
{
    int i;
    for (i = 0; i < MAX_OBJECTS; i++)
        kfree(objects[i]);
    misc_deregister(&objstore_dev);
    pr_info("objstore: device unregistered\n");
}

module_init(objstore_init);
module_exit(objstore_exit);
