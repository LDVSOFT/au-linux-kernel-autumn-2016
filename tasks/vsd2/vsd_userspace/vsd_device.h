#ifndef __VSD_DEV_H
#define __VSD_DEV_H
#include <sys/types.h>
#include <unistd.h>
#include <sys/mman.h>

/*
 * returns:
 *  <>0 on failure
 *  0 on success
 */
int vsd_init();
int vsd_deinit();

/*
 * returns:
 *  <>0 on failure
 *  0 on success
 */
int vsd_get_size(size_t *out_size);
int vsd_set_size(size_t size);

/*
 * returns:
 *  <0 on failure
 *  number of bytes read/written on success
 */
ssize_t vsd_read(char* dst, off_t offset, size_t size);
ssize_t vsd_write(const char* src, off_t offset, size_t size);

/*
 * @offset:
 *  how many bytes to skip from the beginning
 *  of vsd dev mem. Must be a multiple of
 *  system page size.
 *
 * returns:
 *  NULL on failure
 *  pointer to the beginning of mapped vsd dev mem on success
 */
void* vsd_mmap(size_t offset);

/*
 * @addr:
 *  address you got from vsd_mmap
 *
 * @offset:
 *  the same passed to initial vsd_mmap call
 *
 * returns:
 *  -1 on failure
 *  0 on success
 */
int vsd_munmap(void *addr, size_t offset);

#endif //__VSD_DEV_H
