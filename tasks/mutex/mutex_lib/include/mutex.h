#ifndef _MUTEX_LIB_H_
#define _MUTEX_LIB_H_
#include <sys/types.h>
#include <shared_spinlock.h>
#include <mutex_ioctl.h>

typedef struct mutex {
    // TODO store userspace side mutex state here
} mutex_t;

// Return codes
typedef enum {
    MUTEX_OK = 0,
    MUTEX_INTERNAL_ERR = 1
} mutex_err_t;

mutex_err_t mutex_lib_init();
mutex_err_t mutex_lib_deinit();

mutex_err_t mutex_init(mutex_t *m);
mutex_err_t mutex_deinit(mutex_t *m);
mutex_err_t mutex_lock(mutex_t *m);
mutex_err_t mutex_unlock(mutex_t *m);

#endif //_MUTEX_LIB_H_
