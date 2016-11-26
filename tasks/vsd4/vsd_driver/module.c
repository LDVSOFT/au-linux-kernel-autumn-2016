#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <asm/uaccess.h>
#include <uapi/linux/fs.h>
#include <uapi/linux/stat.h>
#include <linux/platform_device.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mutex.h>
#include <linux/interrupt.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/uaccess.h>

#include "../vsd_device/vsd_hw.h"
#include "vsd_ioctl.h"

#define BUFFER_SIZE PAGE_SIZE
#define LOG_TAG "[VSD_CHAR_DEVICE] "

#define VSD_DEV_CMD_QUEUE_MAX_LEN 10

// We add one more element, because our queue only can has (MAX_SIZE - 1) elemets
#define VSD_DEV_CMD_QUEUE_LEN (VSD_DEV_CMD_QUEUE_MAX_LEN + 1)

typedef struct vsd_dev_task {
    char action;
    char* dev_buffer;
    size_t offset;
    size_t size;
    ssize_t result;
    wait_queue_head_t wait_queue;
} vsd_dev_task_t;

typedef struct vsd_dev {
    struct miscdevice mdev;
    struct tasklet_struct dma_op_complete_tsk;
    volatile vsd_hw_regs_t *hwregs;
    spinlock_t lock;
    vsd_dev_task_t *task_queue[VSD_DEV_CMD_QUEUE_LEN];
    int task_queue_head;
    int task_queue_tail;
    wait_queue_head_t wait_queue_has_space;
    vsd_dev_task_t *task_current;
} vsd_dev_t;
static vsd_dev_t *vsd_dev;

#define LOCAL_DEBUG 0
static void print_vsd_dev_hw_regs(vsd_dev_t *vsd_dev)
{
    if (!LOCAL_DEBUG)
        return;

    pr_notice(LOG_TAG "VSD dev hwregs: \n"
            "CMD: %x \n"
            "RESULT: %x \n"
            "TASKLET_VADDR: %llx \n"
            "dma_paddr: %llx \n"
            "dma_size:  %llx \n"
            "dev_offset: %llx \n"
            "dev_size: %llx \n",
            vsd_dev->hwregs->cmd,
            vsd_dev->hwregs->result,
            vsd_dev->hwregs->tasklet_vaddr,
            vsd_dev->hwregs->dma_paddr,
            vsd_dev->hwregs->dma_size,
            vsd_dev->hwregs->dev_offset,
            vsd_dev->hwregs->dev_size
    );
}

/* More control over wait_event routine.
 * Invariants:
 * -> When invoked, callee must have locked the driver.
 * -> When returned, callee will have it back.
 * -> And condition will be true, thus it is checked in locked environment.
 */
#define vsd_dev_wait_for(can_block, queue, condition)                   \
    ({                                                                  \
        int __ret = 0;                                                  \
        wait_queue_t wait;                                              \
        if (can_block)                                                  \
            might_sleep();                                              \
        INIT_LIST_HEAD(&wait.task_list);                                \
        while (1) {                                                     \
            if (condition)                                              \
                break;                                                  \
            if (!can_block) {                                           \
                __ret = -EWOULDBLOCK;                                   \
                break;                                                  \
            }                                                           \
            prepare_to_wait_event(&queue, &wait, TASK_UNINTERRUPTIBLE); \
            spin_unlock_bh(&vsd_dev->lock);                             \
            schedule();                                                 \
            spin_lock_bh(&vsd_dev->lock);                               \
        }                                                               \
        finish_wait(&queue, &wait);                                     \
        __ret;                                                          \
    })

static int vsd_dev_has_space(void) {
    return (vsd_dev->task_queue_tail + 1) % VSD_DEV_CMD_QUEUE_LEN != vsd_dev->task_queue_head;
}

static vsd_dev_task_t* vsd_dev_task_alloc(int can_block) {
    vsd_dev_task_t *res = kmalloc(sizeof(vsd_dev_task_t), can_block ? GFP_KERNEL : GFP_ATOMIC);
    if (res == NULL)
        return NULL;
    res->dev_buffer = NULL;
    res->result = 0;
    init_waitqueue_head(&res->wait_queue);
    return res;
}

static int vsd_dev_count(void) {
    return (vsd_dev->task_queue_tail - vsd_dev->task_queue_head + VSD_DEV_CMD_QUEUE_LEN) % VSD_DEV_CMD_QUEUE_LEN;
}

/*
 * task -- task to commit, must be valid
 * can_block -- can we block while processing
 * non_block_result -- result in case nonblocking task submitted
 */
static ssize_t vsd_dev_commit(vsd_dev_task_t *task, int can_block, ssize_t non_block_result) {
    int ret = 0;

    spin_lock_bh(&vsd_dev->lock);
    ret = vsd_dev_wait_for(can_block, vsd_dev->wait_queue_has_space, vsd_dev_has_space());
    if (ret < 0)
        goto err;

    vsd_dev->task_queue[vsd_dev->task_queue_tail] = task;
    vsd_dev->task_queue_tail = (vsd_dev->task_queue_tail + 1) % VSD_DEV_CMD_QUEUE_LEN;
    pr_info(LOG_TAG "Commit %d to queue, it has %d elemets.\n", task->action, vsd_dev_count());

    if (!can_block) {
        ret = non_block_result;
    } else {
        vsd_dev_wait_for(1, task->wait_queue, task->action & VSD_CMD_DONE);
        ret = task->result;
    }

    if (ret > 0)
        tasklet_schedule(&vsd_dev->dma_op_complete_tsk);
err:
    spin_unlock_bh(&vsd_dev->lock);
    return ret;
}

static ssize_t vsd_dev_read(struct file *filp,
    char __user *read_user_buf, size_t read_size, loff_t *fpos)
{
    int ret = 0;
    vsd_dev_task_t *task;
    if (filp->f_flags & O_NONBLOCK) {
        ret = -EWOULDBLOCK;
        goto err;
    }

    task = vsd_dev_task_alloc(1);
    if (task == NULL) {
        ret = -ENOMEM;
        goto err;
    }
    task->dev_buffer = kmalloc(read_size, GFP_KERNEL);
    if (task->dev_buffer == NULL) {
        ret = -ENOMEM;
        goto err_free;
    }
    task->action = VSD_CMD_READ;
    task->size = read_size;
    task->offset = *fpos;

    ret = vsd_dev_commit(task, 1, 0);
    if (ret > 0) {
        if (copy_to_user(read_user_buf, task->dev_buffer, ret))
            ret = -EFAULT;
        else
            *fpos += ret;
    }

err_free:
    kfree(task->dev_buffer);
    kfree(task);
err:
    return ret;
}

static ssize_t vsd_dev_write(struct file *filp,
    const char __user *write_user_buf, size_t write_size, loff_t *fpos)
{
    int ret = 0;
    int can_block = !(filp->f_flags & O_NONBLOCK);

    vsd_dev_task_t *task = vsd_dev_task_alloc(can_block);
    if (task == NULL) {
        ret = -ENOMEM;
        goto err;
    }
    task->dev_buffer = kmalloc(write_size, can_block ? GFP_KERNEL : GFP_ATOMIC);
    if (task->dev_buffer == NULL) {
        ret = -ENOMEM;
        goto err_free;
    }

    if (!can_block)
        pagefault_disable();
    if (copy_from_user(task->dev_buffer, write_user_buf, write_size))
        ret = -EFAULT;
    if (!can_block)
        pagefault_enable();
    if (ret < 0)
        goto err_free;

    if (can_block) {
        task->action = VSD_CMD_WRITE;
    } else {
        task->action = VSD_CMD_WRITE | VSD_CMD_NONBLOCK;
    }
    task->size = write_size;
    task->offset = *fpos;

    ret = vsd_dev_commit(task, can_block, write_size);
    if (!can_block) {
        if (ret > 0)
            *fpos += ret;
        goto err;
    }

err_free:
    kfree(task->dev_buffer);
    kfree(task);
err:
    return ret;
}

static loff_t vsd_dev_llseek(struct file *filp, loff_t off, int whence)
{
    ssize_t devsize;
    loff_t newpos = 0;
    vsd_dev_task_t *task;
    int ret = 0;
    if (filp->f_flags & O_NONBLOCK) {
        ret = -EWOULDBLOCK;
        goto err;
    }

    task = vsd_dev_task_alloc(1);
    if (task == NULL) {
        ret = -ENOMEM;
        goto err;
    }
    task->action = VSD_CMD_GET_SIZE;

    ret = vsd_dev_commit(task, 1, 0);
    if (ret < 0)
        goto err;
    devsize = ret;
    ret = 0;

    switch(whence) {
        case SEEK_SET:
            newpos = off;
            break;
        case SEEK_CUR:
            newpos = filp->f_pos + off;
            break;
        case SEEK_END:
            newpos = devsize - off;
            break;
        default: /* can't happen */
            return -EINVAL;
    }
    if (newpos < 0) return -EINVAL;
    if (newpos >= devsize)
        newpos = devsize;

    filp->f_pos = newpos;
    return newpos;
err:
    return ret;
}

static long vsd_ioctl_get_size(struct file *filp, vsd_ioctl_get_size_arg_t __user *uarg)
{
    vsd_ioctl_get_size_arg_t arg;
    vsd_dev_task_t *task;

    int ret = 0;
    if (filp->f_flags & O_NONBLOCK) {
        ret = -EWOULDBLOCK;
        goto err;
    }

    task = vsd_dev_task_alloc(1);
    if (task == NULL) {
        ret = -ENOMEM;
        goto err;
    }
    task->action = VSD_CMD_GET_SIZE;

    ret = vsd_dev_commit(task, 1, 0);
    if (ret < 0)
        goto err;
    arg.size = ret;
    ret = 0;
    if (copy_to_user(uarg, &arg, sizeof(arg)))
        ret = -EFAULT;
err:
    return ret;
}

static long vsd_ioctl_set_size(struct file *filp, vsd_ioctl_set_size_arg_t __user *uarg)
{
    vsd_ioctl_set_size_arg_t arg;

    int ret = 0;
    int can_block = !(filp->f_flags & O_NONBLOCK);
    vsd_dev_task_t *task;

    if (!can_block)
        pagefault_disable();
    if (copy_from_user(&arg, uarg, sizeof(arg)))
        ret = -EFAULT;
    if (!can_block)
        pagefault_enable();
    if (ret < 0)
        goto err;

    task = vsd_dev_task_alloc(can_block);
    if (task == NULL) {
        ret = -ENOMEM;
        goto err;
    }
    if (can_block) {
        task->action = VSD_CMD_SET_SIZE;
    } else {
        task->action = VSD_CMD_SET_SIZE | VSD_CMD_NONBLOCK;
    }
    task->size = arg.size;

    ret = vsd_dev_commit(task, can_block, 0);

err:
    return ret;
}

static long vsd_dev_ioctl(struct file *filp, unsigned int cmd,
        unsigned long arg)
{
    switch(cmd) {
        case VSD_IOCTL_GET_SIZE:
            return vsd_ioctl_get_size(filp, (vsd_ioctl_get_size_arg_t __user*)arg);
            break;
        case VSD_IOCTL_SET_SIZE:
            return vsd_ioctl_set_size(filp, (vsd_ioctl_set_size_arg_t __user*)arg);
            break;
        default:
            return -ENOTTY;
    }
}

static unsigned int vsd_dev_poll(struct file *filp, struct poll_table_struct *ptable) {
    int ret = 0;
    poll_wait(filp, &vsd_dev->wait_queue_has_space, ptable);
    spin_lock_bh(&vsd_dev->lock);
    if (vsd_dev_has_space())
        ret = POLLOUT | POLLWRNORM;
    pr_info(LOG_TAG "poll: queue has %d tasks, returning %d.\n", vsd_dev_count(), ret);
    spin_unlock_bh(&vsd_dev->lock);
    return ret;
}

static void vsd_dev_tick_finish(vsd_dev_task_t *task) {
    if (task->result < 0)
        task->action |= VSD_CMD_DONE;
    if (task->action & VSD_CMD_DONE) {
        if (task != vsd_dev->task_queue[vsd_dev->task_queue_head])
            pr_warn(LOG_TAG "NOT A QUEUE HEAD!\n");
        vsd_dev->task_queue_head = (vsd_dev->task_queue_head + 1) % VSD_DEV_CMD_QUEUE_LEN;
        pr_info(LOG_TAG "Removed %d from queue, it has %d elemets.\n", task->action, vsd_dev_count());
        if (task->action & VSD_CMD_NONBLOCK) {
            pr_info(LOG_TAG "Nonblocking task %d done; result = %zd\n", (int)task->action, task->result);
            kfree(task->dev_buffer);
            kfree(task);
        } else {
            pr_info(LOG_TAG "Blocking task %d done; result = %zd\n", (int)task->action, task->result);
            wake_up(&task->wait_queue);
        }
        wake_up(&vsd_dev->wait_queue_has_space);
    }
}

static void vsd_dev_tick_result(void) {
    vsd_dev_task_t *task;

    rmb();
    if (vsd_dev->hwregs->cmd != VSD_CMD_NONE) {
        pr_info(LOG_TAG "Device still busy.\n");
        return;
    }
    if (vsd_dev->task_queue_head == vsd_dev->task_queue_tail) {
        pr_warn(LOG_TAG "No tasks to grab result.\n");
        return;
    }
    task = vsd_dev->task_queue[vsd_dev->task_queue_head];
    if (!(task->action & VSD_CMD_DOING)) {
        pr_warn(LOG_TAG "No active tasks to grab result.\n");
        return;
    }
    task->action &= ~VSD_CMD_DOING;

    pr_info(LOG_TAG "Got result %d from device.\n", vsd_dev->hwregs->result);
    task->result = vsd_dev->hwregs->result;
    task->action |= VSD_CMD_DONE;
    vsd_dev_tick_finish(task);
}

static void vsd_dev_tick_push(void) {
    vsd_dev_task_t *task;

    if (vsd_dev->task_queue_head == vsd_dev->task_queue_tail) {
        pr_info(LOG_TAG "No tasks to push.\n");
        return;
    }
    task = vsd_dev->task_queue[vsd_dev->task_queue_head];

    switch (task->action & VSD_CMD_MASK) {
        case VSD_CMD_READ:
            if (task->offset > vsd_dev->hwregs->dev_size) {
                task->result = -EINVAL;
                break;
            }
            if (task->offset + task->size > vsd_dev->hwregs->dev_size)
                task->size = vsd_dev->hwregs->dev_size - task->offset;
            pr_info(LOG_TAG "Pushing read: offset=%zu size=%zu...\n", task->offset, task->size);
            task->action |= VSD_CMD_DOING;
            vsd_dev->hwregs->dev_offset = task->offset;
            vsd_dev->hwregs->dma_paddr = virt_to_phys(task->dev_buffer);
            vsd_dev->hwregs->dma_size = task->size;
            wmb();
            vsd_dev->hwregs->cmd = VSD_CMD_READ;
            wmb();

            break;
        case VSD_CMD_WRITE:
            if (task->offset >= vsd_dev->hwregs->dev_size) {
                task->result = -EINVAL;
                break;
            }
            if (task->offset + task->size > vsd_dev->hwregs->dev_size)
                task->size = vsd_dev->hwregs->dev_size - task->offset;
            pr_info(LOG_TAG "Pushing write: offset=%zu size=%zu...\n", task->offset, task->size);
            task->action |= VSD_CMD_DOING;
            vsd_dev->hwregs->dev_offset = task->offset;
            vsd_dev->hwregs->dma_paddr = virt_to_phys(task->dev_buffer);
            vsd_dev->hwregs->dma_size = task->size;
            wmb();
            vsd_dev->hwregs->cmd = VSD_CMD_WRITE;
            wmb();

            break;
        case VSD_CMD_SET_SIZE:
            pr_info(LOG_TAG "Pushing set size: size=%zu...\n", task->size);
            task->action |= VSD_CMD_DOING;
            vsd_dev->hwregs->dev_offset = task->size;
            wmb();
            vsd_dev->hwregs->cmd = VSD_CMD_SET_SIZE;
            wmb();

            break;
        case VSD_CMD_GET_SIZE:
            pr_info(LOG_TAG "Doing get size in place.\n");
            task->action |= VSD_CMD_DONE;
            task->result = vsd_dev->hwregs->dev_size;
            break;
        default:
            pr_warn(LOG_TAG "Unknown action in queue: %d\n", task->action);
    }
    vsd_dev_tick_finish(task);
}

static void vsd_dev_tick(unsigned long unused) {
    (void)unused;
    spin_lock_bh(&vsd_dev->lock);
    vsd_dev_tick_result();
    vsd_dev_tick_push();
    spin_unlock_bh(&vsd_dev->lock);
}

static int vsd_dev_open(struct inode *inode, struct file *filp)
{
    pr_notice(LOG_TAG "vsd dev opened\n");
    return 0;
}

static int vsd_dev_release(struct inode *inode, struct file *filp)
{
    pr_notice(LOG_TAG "vsd dev closed\n");
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
    .poll = vsd_dev_poll
};

#undef LOG_TAG
#define LOG_TAG "[VSD_DRIVER] "

static int vsd_driver_probe(struct platform_device *pdev)
{
    int ret = 0;
    struct resource *vsd_control_regs_res = NULL;
    pr_notice(LOG_TAG "probing for device %s\n", pdev->name);

    vsd_dev = (vsd_dev_t*)
        kzalloc(sizeof(*vsd_dev), GFP_KERNEL);
    if (!vsd_dev) {
        ret = -ENOMEM;
        pr_warn(LOG_TAG "Can't allocate memory\n");
        goto error_alloc;
    }
    tasklet_init(&vsd_dev->dma_op_complete_tsk,
            vsd_dev_tick, 0);
    spin_lock_init(&vsd_dev->lock);
    init_waitqueue_head(&vsd_dev->wait_queue_has_space);
    vsd_dev->task_queue_head = vsd_dev->task_queue_tail = 0;
    vsd_dev->mdev.minor = MISC_DYNAMIC_MINOR;
    vsd_dev->mdev.name = "vsd";
    vsd_dev->mdev.fops = &vsd_dev_fops;
    vsd_dev->mdev.mode = S_IRUSR | S_IRGRP | S_IROTH
        | S_IWUSR| S_IWGRP | S_IWOTH;

    if ((ret = misc_register(&vsd_dev->mdev)))
        goto error_misc_reg;

    vsd_control_regs_res = platform_get_resource_byname(
            pdev, IORESOURCE_REG, "control_regs");
    if (!vsd_control_regs_res) {
        ret = -ENOMEM;
        goto error_get_res;
    }
    vsd_dev->hwregs = (volatile vsd_hw_regs_t*)
        phys_to_virt(vsd_control_regs_res->start);

    spin_lock_bh(&vsd_dev->lock);
    vsd_dev->hwregs->tasklet_vaddr = &vsd_dev->dma_op_complete_tsk;
    wmb();
    spin_unlock_bh(&vsd_dev->lock);

    print_vsd_dev_hw_regs(vsd_dev);
    pr_notice(LOG_TAG "VSD dev with MINOR %u"
        " has started successfully\n", vsd_dev->mdev.minor);
    return 0;

error_get_res:
    misc_deregister(&vsd_dev->mdev);
error_misc_reg:
    spin_unlock_bh(&vsd_dev->lock);
    kfree(vsd_dev);
    vsd_dev = NULL;
error_alloc:
    return ret;
}

static int vsd_driver_remove(struct platform_device *dev)
{
    // module can't be unloaded if its users has even single
    // opened fd
    spin_lock_bh(&vsd_dev->lock);
    pr_notice(LOG_TAG "removing device %s\n", dev->name);
    vsd_dev->hwregs->tasklet_vaddr = NULL;
    wmb();
    spin_unlock_bh(&vsd_dev->lock);
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
    // This indirectly calls vsd_driver_remove
    platform_driver_unregister(&vsd_driver);
}

module_init(vsd_driver_init);
module_exit(vsd_driver_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("AU Virtual Storage Device driver module");
MODULE_AUTHOR("Kernel hacker!");
