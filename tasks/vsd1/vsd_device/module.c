#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include <uapi/linux/fs.h>
#include <uapi/linux/stat.h>
#include <asm/io.h>

#define LOG_TAG "[VSD_PLAT_DEVICE] "

static unsigned long buf_size = 4096;
module_param(buf_size, ulong, S_IRUGO);

typedef struct vsd_plat_device {
    struct platform_device pdev;
    char *vbuf;
    phys_addr_t pbuf;
    size_t buf_size;
} vsd_plat_device_t;

#define VSD_RES_BUF_IX 0
static struct resource vsd_plat_device_resources[] = {
    [VSD_RES_BUF_IX] = {
        .name = "buffer",
        .start = 0x0,
        .end = 0x0,
        .flags = IORESOURCE_MEM
    },
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

static int __init vsd_dev_module_init(void)
{
    int ret = 0;

    dev.vbuf = (char*)kzalloc(buf_size, GFP_KERNEL);
    if (!dev.vbuf) {
        ret = -ENOMEM;
        pr_warn(LOG_TAG "Can't allocate memory\n");
        goto error_alloc;
    }
    dev.pbuf = virt_to_phys(dev.vbuf);
    dev.buf_size = buf_size;
    dev.pdev.resource[VSD_RES_BUF_IX].start = dev.pbuf;
    dev.pdev.resource[VSD_RES_BUF_IX].end = dev.pbuf + dev.buf_size - 1;

    if ((ret = platform_device_register(&dev.pdev)))
        goto error_reg;

    pr_notice("VSD device with storage at vaddr %p of size %zu was started",
            dev.vbuf, dev.buf_size);
    return 0;
error_reg:
    kfree(dev.vbuf);
error_alloc:
    return ret;
}

static void vsd_plat_device_release(struct device *gen_dev)
{
    pr_notice(LOG_TAG "vsd_dev_release\n");
}

static void __exit vsd_dev_module_exit(void)
{
    pr_notice(LOG_TAG "vsd_dev_destroy\n");
    platform_device_unregister(&dev.pdev);
    kfree(dev.vbuf);
}

module_init(vsd_dev_module_init);
module_exit(vsd_dev_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("AU Virtual Storage Device module");
MODULE_AUTHOR("Kernel hacker!");
