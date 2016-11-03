#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <uapi/linux/fs.h>
#include <uapi/linux/stat.h>
#include <linux/platform_device.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include "vsd_ioctl.h"

#define LOG_TAG "[VSD_CHAR_DEVICE] "

typedef struct vsd_dev {
    struct miscdevice mdev;
    char *vbuf;
    size_t buf_size;
    size_t max_buf_size;
    unsigned int mmaped_count;
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
    if (*fpos >= vsd_dev->buf_size)
        return 0;

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
    if (copy_from_user(&arg, uarg, sizeof(arg)))
        return -EFAULT;

    arg.size = vsd_dev->buf_size;

    if (copy_to_user(uarg, &arg, sizeof(arg)))
        return -EFAULT;
    return 0;
}

static long vsd_ioctl_set_size(vsd_ioctl_set_size_arg_t __user *uarg)
{
    vsd_ioctl_set_size_arg_t arg;
    if (vsd_dev->mmaped_count != 0)
        return -EBUSY;

    if (copy_from_user(&arg, uarg, sizeof(arg)))
        return -EFAULT;

    if (arg.size <= vsd_dev->max_buf_size) {
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

static void vsd_dev_vm_open(struct vm_area_struct *uvma) {
    vsd_dev->mmaped_count++;
}

static void vsd_dev_vm_close(struct vm_area_struct *uvma) {
    vsd_dev->mmaped_count--;
}

static struct vm_operations_struct vsd_dev_vma_ops = {
    .open = vsd_dev_vm_open,
    .close = vsd_dev_vm_close
};

static int map_vmalloc_range(struct vm_area_struct *uvma, void *kaddr, size_t size)
{
    unsigned long uaddr = uvma->vm_start;
    if (!PAGE_ALIGNED(uaddr) || !PAGE_ALIGNED(kaddr)
            || !PAGE_ALIGNED(size))
        return -EINVAL;

    for (; uaddr != uvma->vm_end; uaddr += PAGE_SIZE, kaddr += PAGE_SIZE) {
        struct page *p = vmalloc_to_page(kaddr);
        int ret = vm_insert_page(uvma, uaddr, p);
        if (ret) {
            return ret;
        }
    }

    uvma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
    return 0;
}

static int vsd_dev_mmap(struct file *filp, struct vm_area_struct *vma)
{
    int ret = 0;
    unsigned long offset, size;

    size = PAGE_ALIGN(vma->vm_end - vma->vm_start);
    offset = vma->vm_pgoff << PAGE_SHIFT;

    if ((offset + size) > vsd_dev->buf_size)
       return -EINVAL;

    if (!(vma->vm_flags & VM_SHARED))
        return -EINVAL;

    if ((ret = map_vmalloc_range(vma, vsd_dev->vbuf + offset, size)))
        return ret;

    vma->vm_ops = &vsd_dev_vma_ops;
    vsd_dev_vm_open(vma);

    return 0;
}

static struct file_operations vsd_dev_fops = {
    .owner = THIS_MODULE,
    .open = vsd_dev_open,
    .release = vsd_dev_release,
    .read = vsd_dev_read,
    .write = vsd_dev_write,
    .llseek = vsd_dev_llseek,
    .unlocked_ioctl = vsd_dev_ioctl,
    .mmap = vsd_dev_mmap
};

#undef LOG_TAG
#define LOG_TAG "[VSD_DRIVER] "

static int vsd_driver_probe(struct platform_device *pdev)
{
    int ret = 0;
    struct resource *vsd_phy_mem_buf_res = NULL;
    pr_notice(LOG_TAG "probing for device %s\n", pdev->name);

    vsd_dev = (vsd_dev_t*)
        kzalloc(sizeof(*vsd_dev), GFP_KERNEL);
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
        platform_get_resource_byname(pdev, IORESOURCE_REG, "buffer");
    if (!vsd_phy_mem_buf_res) {
        ret = -ENOMEM;
        goto error_get_buf;
    }
    vsd_dev->vbuf = (char*)vsd_phy_mem_buf_res->start;
    vsd_dev->max_buf_size = resource_size(vsd_phy_mem_buf_res);
    vsd_dev->buf_size = vsd_dev->max_buf_size;

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
    return platform_driver_register(&vsd_driver);
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
