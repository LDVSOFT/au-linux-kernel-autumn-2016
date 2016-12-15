#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/platform_device.h>
#include <linux/miscdevice.h>
#include <uapi/linux/fs.h>
#include <uapi/linux/stat.h>
#include <asm/io.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/err.h>
#include <linux/wait.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <asm/barrier.h>
#include "vsd_hw.h"

#define LOG_TAG "[VSD_PLAT_DEVICE] "

static unsigned long buf_size = 2 * PAGE_SIZE;
module_param(buf_size, ulong, S_IRUGO);

typedef struct vsd_plat_device {
    struct platform_device pdev;
    struct task_struct *kthread;
    char *vbuf;
    size_t buf_size;
    volatile vsd_hw_regs_t *hwregs;
} vsd_plat_device_t;

#define VSD_RES_REGS_IX 0
static struct resource vsd_plat_device_resources[] = {
    [VSD_RES_REGS_IX] = {
        .name = "control_regs",
        .start = 0x0,
        .end = 0x0,
        .flags = IORESOURCE_REG
    }
};

static void vsd_plat_device_release(struct device *gen_dev);

static vsd_plat_device_t dev = {
    .pdev = {
        .name = "au-vsd",
        .num_resources = ARRAY_SIZE(vsd_plat_device_resources),
        .resource = vsd_plat_device_resources,
        .dev = {
            .release = vsd_plat_device_release
        }
    }
};

static ssize_t vsd_dev_read(char *dst, size_t dst_size, size_t offset) {
    if (offset + dst_size > dev.buf_size)
        dst_size = dev.buf_size - offset;

    memcpy(dst, dev.vbuf + offset, dst_size);
    return dst_size;
}

static ssize_t vsd_dev_write(char *src, size_t src_size, size_t offset) {
    if (offset + src_size > dev.buf_size)
        src_size = dev.buf_size - offset;

    memcpy(dev.vbuf + offset, src, src_size);
    return src_size;
}

static ssize_t vsd_dev_set_size(size_t size)
{
    if (size > dev.buf_size)
        return -EINVAL;
    dev.buf_size = size;
    return 0;
}

static int vsd_dev_cmd_poll_kthread_func(void *data)
{
    ssize_t ret = 0;
    while(!kthread_should_stop()) {
        mb();
        int cmd = dev.hwregs->cmd;
        switch(cmd) {
            case VSD_CMD_READ:
                ret = vsd_dev_read(
                        phys_to_virt((phys_addr_t)dev.hwregs->dma_paddr),
                        (size_t)dev.hwregs->dma_size,
                        (size_t)dev.hwregs->dev_offset
                );
                break;
            case VSD_CMD_WRITE:
                ret = vsd_dev_write(
                        phys_to_virt((phys_addr_t)dev.hwregs->dma_paddr),
                        (size_t)dev.hwregs->dma_size,
                        (size_t)dev.hwregs->dev_offset
                );
                break;
            case VSD_CMD_SET_SIZE:
                ret = vsd_dev_set_size((size_t)dev.hwregs->dev_offset);
                break;
        }

        if (cmd != VSD_CMD_NONE) {
            dev.hwregs->result = ret;
            dev.hwregs->cmd = VSD_CMD_NONE;
            dev.hwregs->dev_size = dev.buf_size;
            wmb();
            tasklet_schedule((struct tasklet_struct*)dev.hwregs->tasklet_vaddr);
        }
        // Sleep one sec not to waste CPU on polling
        ssleep(1);
    }
    pr_notice(LOG_TAG "cmd poll thread exited");
    return 0;
}

static int __init vsd_dev_module_init(void)
{
    int ret = 0;

    dev.hwregs = kmalloc(sizeof(*dev.hwregs), GFP_KERNEL);
    if (!dev.hwregs) {
        ret = -ENOMEM;
        pr_warn(LOG_TAG "Can't allocate memory\n");
        goto error_alloc_hw;
    }

    dev.vbuf = (char*)vzalloc(buf_size);
    if (!dev.vbuf) {
        ret = -ENOMEM;
        pr_warn(LOG_TAG "Can't allocate memory\n");
        goto error_alloc_buf;
    }
    dev.kthread = kthread_create(vsd_dev_cmd_poll_kthread_func,
            NULL, "vsd_poll_kthread");
    if (IS_ERR_OR_NULL(dev.kthread)) {
        goto error_thread;
    }

    dev.buf_size = buf_size;
    dev.hwregs->cmd = VSD_CMD_NONE;
    dev.hwregs->dev_size = dev.buf_size;
    dev.pdev.resource[VSD_RES_REGS_IX].start =
        virt_to_phys(dev.hwregs);
    dev.pdev.resource[VSD_RES_REGS_IX].end =
        virt_to_phys(dev.hwregs) + sizeof(dev.hwregs) - 1;
    wmb();

    if ((ret = platform_device_register(&dev.pdev)))
        goto error_reg;

    wake_up_process(dev.kthread);

    pr_notice("VSD device with storage at vaddr %p of size %zu \n"
            "and control regs at %p was started\n",
            dev.vbuf, dev.buf_size, dev.hwregs);
    return 0;

error_reg:
    kthread_stop(dev.kthread);
error_thread:
    vfree(dev.vbuf);
error_alloc_buf:
    kfree((void*)dev.hwregs);
error_alloc_hw:
    return ret;
}

static void vsd_plat_device_release(struct device *gen_dev)
{
    pr_notice(LOG_TAG "vsd_dev_release\n");
}

static void __exit vsd_dev_module_exit(void)
{
    pr_notice(LOG_TAG "vsd_dev_destroy\n");
    kthread_stop(dev.kthread);
    platform_device_unregister(&dev.pdev);
    vfree(dev.vbuf);
    kfree((void*)dev.hwregs);
}

module_init(vsd_dev_module_init);
module_exit(vsd_dev_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("AU Virtual Storage Device module");
MODULE_AUTHOR("Kernel hacker!");
