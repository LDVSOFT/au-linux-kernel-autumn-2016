#ifndef _SHARED_SPINLOCK_H_
#define _SHARED_SPINLOCK_H_

#define SHARED_SPIN_TRY_LOCK_NUM_ITERS 1000
#define cpu_wmb() do { \
    asm volatile("sfence"); \
} while (0)
#define cpu_relax() do { \
    asm volatile("pause\n":::); \
} while (0)

typedef struct shared_spinlock {
    int value;
} shared_spinlock_t;

static inline void shared_spinlock_init(shared_spinlock_t *lock)
{
    lock->value = 0;
    cpu_wmb();
}

static inline int shared_spin_islocked(shared_spinlock_t *lock)
{
    return __sync_bool_compare_and_swap(&lock->value, 1, 1);
}

static inline int shared_spin_trylock(shared_spinlock_t *lock)
{
    size_t tried = 0;
    while (tried < SHARED_SPIN_TRY_LOCK_NUM_ITERS) {
        if (__sync_bool_compare_and_swap(&lock->value, 0, 1)) {
            return 1;
        }
        ++tried;
        cpu_relax();
    }
    return 0;
}

static inline void shared_spin_lock(shared_spinlock_t *lock)
{
    while (!shared_spin_trylock(lock)) {}
}

static inline int shared_spin_unlock(shared_spinlock_t *lock)
{
    return __sync_bool_compare_and_swap(&lock->value, 1, 0);
}

#endif //_SHARED_SPINLOCK_H_
