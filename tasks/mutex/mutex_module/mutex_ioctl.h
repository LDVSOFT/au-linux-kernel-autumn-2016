#ifndef _MUTEX_UAPI_H
#define _MUTEX_UAPI_H

#ifdef __KERNEL__
#include <asm/ioctl.h>
#include "shared_spinlock.h"
#else
#include <sys/ioctl.h>
#include <stddef.h>
#include <shared_spinlock.h>
#endif //__KERNEL__

#define MUTEX_IOCTL_MAGIC 'M'

// TODO define mutex dev IOCTL interface here
// Example:

/*
typedef unsigned long mutex_id_t;

typedef struct mutex_ioctl_lock_create_arg {
    mutex_id_t id; // out param
} mutex_ioctl_lock_create_arg_t;

#define MUTEX_IOCTL_LOCK_CREATE \
    _IOW(MUTEX_IOCTL_MAGIC, 1, mutex_ioctl_lock_create_arg_t)
*/

#endif //_VSD_UAPI_H
