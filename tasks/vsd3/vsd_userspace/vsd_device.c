#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <vsd_ioctl.h>
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

ssize_t vsd_read(char* dst, size_t size)
{
    if (lseek(vsd_fd, 0, SEEK_SET) == (off_t)-1)
        return -1;
    return read(vsd_fd, dst, size);
}

ssize_t vsd_write(const char* src, size_t size)
{
    if (lseek(vsd_fd, 0, SEEK_SET) == (off_t)-1)
        return -1;
    return write(vsd_fd, src, size);
}
