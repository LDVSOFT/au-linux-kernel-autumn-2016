#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <vsd_ioctl.h>
#include <poll.h>
#include "vsd_device.h"

static int vsd_fd = -1;

int vsd_init()
{
    vsd_fd = open("/dev/vsd", O_RDWR);
    return vsd_fd < 0 ? -1 : 0;
}

int vsd_deinit()
{
    return close(vsd_fd);
}

int vsd_set_nonblocking(void)
{
    int ret;
    ret = fcntl(vsd_fd, F_GETFL);
    if (ret < 0)
        return ret;
    return fcntl(vsd_fd, F_SETFL, ret | O_NONBLOCK);
}

int vsd_set_blocking(void)
{
    int ret;
    ret = fcntl(vsd_fd, F_GETFL);
    if (ret < 0)
        return ret;
    return fcntl(vsd_fd, F_SETFL, ret &(~O_NONBLOCK));
}

int vsd_get_size(size_t *out_size)
{
    vsd_ioctl_get_size_arg_t arg;
    int ret = ioctl(vsd_fd, VSD_IOCTL_GET_SIZE, &arg);
    if (!ret) {
        *out_size = arg.size;
    }
    return ret;
}

int vsd_set_size(size_t size)
{
    vsd_ioctl_set_size_arg_t arg;
    arg.size = size;
    int ret = ioctl(vsd_fd, VSD_IOCTL_SET_SIZE, &arg);
    return ret;
}

ssize_t vsd_read(char* dst, size_t size, off_t offset)
{
    return pread(vsd_fd, dst, size, offset);
}

ssize_t vsd_write(const char* src, size_t size, off_t offset)
{
    return pwrite(vsd_fd, src, size, offset);
}

int vsd_wait_nonblock_write(void)
{
    static struct pollfd fds[1];
    int ret;
    fds[0].fd = vsd_fd;
    fds[0].events = POLLOUT | POLLWRNORM;
    fds[0].revents = 0;
    ret = poll(fds, 1, -1);
    if (ret < 0)
        return ret;
    if (ret != 1)
        return 1;
    if ((fds[0].revents & fds[0].events) == 0)
        return 2;
    return 0;
}
