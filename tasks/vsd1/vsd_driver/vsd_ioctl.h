#ifndef _VSD_UAPI_H
#define _VSD_UAPI_H

#ifdef __KERNEL__
#include <asm/ioctl.h>
#else
#include <sys/ioctl.h>
#include <stddef.h>
#endif //__KERNEL__

#define VSD_IOCTL_MAGIC 'V'

typedef struct vsd_ioctl_get_size_arg {
    size_t size;
} vsd_ioctl_get_size_arg_t;

typedef struct vsd_ioctl_set_size_arg {
    size_t size;
} vsd_ioctl_set_size_arg_t;

#define VSD_IOCTL_GET_SIZE \
    _IOR(VSD_IOCTL_MAGIC, 1, vsd_ioctl_get_size_arg_t)
#define VSD_IOCTL_SET_SIZE \
    _IOW(VSD_IOCTL_MAGIC, 2, vsd_ioctl_set_size_arg_t)

#endif //_VSD_UAPI_H
