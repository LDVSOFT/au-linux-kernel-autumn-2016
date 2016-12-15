#ifndef __VSD_DEV_H
#define __VSD_DEV_H

// int return value: 0 on success, otherwise - fail
int vsd_init();
int vsd_deinit();

int vsd_get_size(size_t *out_size);
int vsd_set_size(size_t size);

// return value: <0 - fail,
// otherwise number of bytes read/written
ssize_t vsd_read(char* dst, size_t size);
ssize_t vsd_write(const char* src, size_t size);

#endif //__VSD_DEV_H
