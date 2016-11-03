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

#define LOG_TAG "[VSD_PLAT_DEVICE] "

static unsigned long buf_size = 8 * PAGE_SIZE;
module_param(buf_size, ulong, S_IRUGO);

typedef struct vsd_plat_device {
    struct platform_device pdev;
    char *vbuf;
    size_t buf_size;
} vsd_plat_device_t;

#define VSD_RES_BUF_IX 0
static struct resource vsd_plat_device_resources[] = {
    [VSD_RES_BUF_IX] = {
        .name = "buffer",
        .start = 0x0,
        .end = 0x0,
        .flags = IORESOURCE_REG
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

    dev.vbuf = (char*)vzalloc(buf_size);
    if (!dev.vbuf) {
        ret = -ENOMEM;
        pr_warn(LOG_TAG "Can't allocate memory\n");
        goto error_alloc;
    }
    dev.buf_size = buf_size;
    dev.pdev.resource[VSD_RES_BUF_IX].start =
        (unsigned long)dev.vbuf;
    dev.pdev.resource[VSD_RES_BUF_IX].end =
        (unsigned long)dev.vbuf + dev.buf_size - 1;

    if ((ret = platform_device_register(&dev.pdev)))
        goto error_reg;

    pr_notice("VSD device with storage at vaddr %p of size %zu was started",
            dev.vbuf, dev.buf_size);
    return 0;
error_reg:
    vfree(dev.vbuf);
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
    vfree(dev.vbuf);
}

module_init(vsd_dev_module_init);
module_exit(vsd_dev_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("AU Virtual Storage Device module");
MODULE_AUTHOR("Kernel hacker!");
