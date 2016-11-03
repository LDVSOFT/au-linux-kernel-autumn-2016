#include "vsd_device.h"
#include "vsd_ioctl.h"
#include "fcntl.h"
#include "unistd.h"
#include "sys/mman.h"

#include <stdio.h>

static int fd;

int vsd_init()
{
    fd = open("/dev/vsd", O_RDWR);
    printf("!! init: fd = %d\n", fd);
    if (fd < 0)
        return -1;
    return 0;
}

int vsd_deinit()
{
    close(fd);
    return 0;
}

int vsd_get_size(size_t *out_size)
{
    vsd_ioctl_get_size_arg_t arg;
    int res = ioctl(fd, VSD_IOCTL_GET_SIZE, &arg);
    if (res == -1)
        return res;
    *out_size = arg.size;
    return res;
}

int vsd_set_size(size_t size)
{
    vsd_ioctl_set_size_arg_t arg;
    arg.size = size;
    int res = ioctl(fd, VSD_IOCTL_SET_SIZE, &arg);
    printf("!! set size: res = %d\n", res);
    return res;
}

ssize_t vsd_read(char* dst, off_t offset, size_t size)
{
    int res = lseek(fd, offset, SEEK_SET);
    if (res == -1)
        return res;
    return read(fd, dst, size);
}

ssize_t vsd_write(const char* src, off_t offset, size_t size)
{
    int res = lseek(fd, offset, SEEK_SET);
    printf("!! write: lseek = %d\n", res);
    if (res == -1)
        return res;
    res = write(fd, src, size);
    printf("!! write: res = %d\n", res);
}

void* vsd_mmap(size_t offset)
{
    size_t size;
    int res = vsd_get_size(&size);
    if (res < 0)
        return NULL;
    return mmap(NULL, size - offset, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);
}

int vsd_munmap(void* addr, size_t offset)
{
    size_t size;
    int ret = vsd_get_size(&size);
    if (ret < 0)
        return size;
    return munmap(addr, size - offset);
}
