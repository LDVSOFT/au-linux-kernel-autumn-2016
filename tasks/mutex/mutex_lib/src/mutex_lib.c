#include <mutex.h>

mutex_err_t mutex_init(mutex_t *m)
{
    // TODO initialize userspace side mutex state
    // and create kernel space mutex state
    return MUTEX_INTERNAL_ERR;
}

mutex_err_t mutex_deinit(mutex_t *m)
{
    // TODO destroy kernel side mutex state
    // and deinitialize userspace side.
    return MUTEX_INTERNAL_ERR;
}

mutex_err_t mutex_lock(mutex_t *m)
{
    // TODO lock spinlock here.
    // If not successful then go to sleep
    // in kernel.
    return MUTEX_INTERNAL_ERR;
}

mutex_err_t mutex_unlock(mutex_t *m)
{
    // TODO unlock spinlock
    // and wakeup one kernel side waiter
    // if it exists.
    return MUTEX_INTERNAL_ERR;
}

mutex_err_t mutex_lib_init()
{
    // TODO create current process mutex
    // registry on kernel side
    return MUTEX_INTERNAL_ERR;
}

mutex_err_t mutex_lib_deinit()
{
    // TODO destroy current process mutex
    // registry on kernel side
    return MUTEX_INTERNAL_ERR;
}
