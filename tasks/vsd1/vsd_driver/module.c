#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <uapi/linux/fs.h>
#include <uapi/linux/stat.h>
#include <linux/platform_device.h>
#include <linux/ioport.h>
#include "vsd_ioctl.h"

#define LOG_TAG "[VSD_CHAR_DEVICE] "

typedef struct vsd_dev {
    struct miscdevice mdev;
    char *vbuf;
    size_t buf_size;
} vsd_dev_t;
static vsd_dev_t *vsd_dev;

static int vsd_dev_open(struct inode *inode, struct file *filp)
{
    pr_notice(LOG_TAG "opened\n");
    return 0;
}

static int vsd_dev_release(struct inode *inode, struct file *filp)
{
    pr_notice(LOG_TAG "closed\n");
    return 0;
}

static ssize_t vsd_dev_read(struct file *filp,
    char __user *read_user_buf, size_t read_size, loff_t *fpos)
{
    // Specially made request with 0 bytes left OK
    if (*fpos > vsd_dev->buf_size)
        return -EINVAL;

    if (*fpos + read_size >= vsd_dev->buf_size)
        read_size = vsd_dev->buf_size - *fpos;

    if (copy_to_user(read_user_buf, vsd_dev->vbuf + *fpos, read_size))
        return -EFAULT;

    *fpos += read_size;
    return read_size;
}

static ssize_t vsd_dev_write(struct file *filp,
    const char __user *write_user_data, size_t write_size, loff_t *fpos)
{
    if (*fpos >= vsd_dev->buf_size)
        return -EINVAL;

    if (*fpos + write_size >= vsd_dev->buf_size)
        write_size = vsd_dev->buf_size - *fpos;

    if (copy_from_user(vsd_dev->vbuf + *fpos, write_user_data, write_size))
        return -EFAULT;

    *fpos += write_size;
    return write_size;
}

static loff_t vsd_dev_llseek(struct file *filp, loff_t off, int whence)
{
    loff_t newpos = 0;

    switch(whence) {
        case SEEK_SET:
            newpos = off;
            break;
        case SEEK_CUR:
            newpos = filp->f_pos + off;
            break;
        case SEEK_END:
            newpos = vsd_dev->buf_size - off;
            break;
        default: /* can't happen */
            return -EINVAL;
    }
    if (newpos < 0) return -EINVAL;
    if (newpos >= vsd_dev->buf_size)
        newpos = vsd_dev->buf_size;

    filp->f_pos = newpos;
    return newpos;
}

static long vsd_ioctl_get_size(vsd_ioctl_get_size_arg_t __user *uarg)
{
    vsd_ioctl_get_size_arg_t arg;
    arg.size = vsd_dev->buf_size;
    if (copy_to_user(uarg, &arg, sizeof(arg)))
        return -EFAULT;
    return 0;
}

static long vsd_ioctl_set_size(vsd_ioctl_set_size_arg_t __user *uarg)
{
    vsd_ioctl_set_size_arg_t arg;
    if (copy_from_user(&arg, uarg, sizeof(arg)))
        return -EFAULT;

    if (arg.size <= vsd_dev->buf_size) {
        vsd_dev->buf_size = arg.size;
        return 0;
    } else return -ENOMEM;
}

static long vsd_dev_ioctl(struct file *filp, unsigned int cmd,
        unsigned long arg)
{
    switch(cmd) {
        case VSD_IOCTL_GET_SIZE:
            return vsd_ioctl_get_size((vsd_ioctl_get_size_arg_t __user*)arg);
            break;
        case VSD_IOCTL_SET_SIZE:
            return vsd_ioctl_set_size((vsd_ioctl_set_size_arg_t __user*)arg);
            break;
        default:
            return -ENOTTY;
    }
}

static struct file_operations vsd_dev_fops = {
    .owner = THIS_MODULE,
    .open = vsd_dev_open,
    .release = vsd_dev_release,
    .read = vsd_dev_read,
    .write = vsd_dev_write,
    .llseek = vsd_dev_llseek,
    .unlocked_ioctl = vsd_dev_ioctl
};

#undef LOG_TAG
#define LOG_TAG "[VSD_DRIVER] "

static int vsd_driver_probe(struct platform_device *pdev)
{
    int ret = 0;
    struct resource *vsd_phy_mem_buf_res = NULL;
    pr_notice(LOG_TAG "probing for device %s\n", pdev->name);

    vsd_dev = (vsd_dev_t*)kzalloc(sizeof(vsd_dev_t), GFP_KERNEL);
    if (!vsd_dev) {
        ret = -ENOMEM;
        pr_warn(LOG_TAG "Can't allocate memory\n");
        goto error_alloc;
    }
    vsd_dev->mdev.minor = MISC_DYNAMIC_MINOR;
    vsd_dev->mdev.name = "vsd";
    vsd_dev->mdev.fops = &vsd_dev_fops;
    vsd_dev->mdev.mode = S_IRUSR | S_IRGRP | S_IROTH
        | S_IWUSR| S_IWGRP | S_IWOTH;

    if ((ret = misc_register(&vsd_dev->mdev)))
        goto error_misc_reg;

    vsd_phy_mem_buf_res =
        platform_get_resource_byname(pdev, IORESOURCE_MEM, "buffer");
    if (!vsd_phy_mem_buf_res) {
        ret = -ENOMEM;
        goto error_get_buf;
    }
    vsd_dev->vbuf = phys_to_virt(vsd_phy_mem_buf_res->start);
    vsd_dev->buf_size = vsd_phy_mem_buf_res->end - vsd_phy_mem_buf_res->start + 1;

    pr_notice(LOG_TAG "VSD dev with MINOR %u"
        " has started successfully\n", vsd_dev->mdev.minor);
    return 0;

error_get_buf:
    misc_deregister(&vsd_dev->mdev);
error_misc_reg:
    kfree(vsd_dev);
    vsd_dev = NULL;
error_alloc:
    return ret;
}

static int vsd_driver_remove(struct platform_device *dev)
{
    pr_notice(LOG_TAG "removing device %s\n", dev->name);
    misc_deregister(&vsd_dev->mdev);
    kfree(vsd_dev);
    vsd_dev = NULL;
    return 0;
}

static struct platform_driver vsd_driver = {
    .probe = vsd_driver_probe,
    .remove = vsd_driver_remove,
    .driver = {
        .name = "au-vsd",
        .owner = THIS_MODULE,
    }
};

static int __init vsd_driver_init(void)
{
    int ret = platform_driver_register(&vsd_driver);
    return ret;
}

static void __exit vsd_driver_exit(void)
{
    platform_driver_unregister(&vsd_driver);
}

module_init(vsd_driver_init);
module_exit(vsd_driver_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("AU Virtual Storage Device driver module");
MODULE_AUTHOR("Kernel hacker!");
