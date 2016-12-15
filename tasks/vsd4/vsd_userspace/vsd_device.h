#ifndef __VSD_DEV_H
#define __VSD_DEV_H

#include <sys/types.h>
#include <unistd.h>

// int return value: 0 on success, otherwise - fail
int vsd_init();
int vsd_deinit();

int vsd_set_blocking(void);
int vsd_set_nonblocking(void);
int vsd_wait_nonblock_write(void);

int vsd_get_size(size_t *out_size);
int vsd_set_size(size_t size);

// return value: <0 - fail, errno is set,
// otherwise number of bytes read/written
ssize_t vsd_read(char* dst, size_t size, off_t offset);
ssize_t vsd_write(const char* src, size_t size, off_t offset);

#endif //__VSD_DEV_H
