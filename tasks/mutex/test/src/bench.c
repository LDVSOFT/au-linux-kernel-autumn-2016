#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define COUNTER_TARGET (1000 * 1000 * 10)

size_t shared_counter = 0;

#ifdef USE_AU_MUTEX
#include <mutex.h>
mutex_t shared_counter_mutex;
#else
pthread_mutex_t shared_counter_mutex =
    PTHREAD_MUTEX_INITIALIZER;

#define mutex_init(m)
#define mutex_lock(m) pthread_mutex_lock(m)
#define mutex_unlock(m) pthread_mutex_unlock(m)

#define MUTEX_OK 1
#define mutex_lib_init() MUTEX_OK
#define mutex_lib_deinit()
#endif

void* bench_thread_func(void *ignored)
{
    (void)ignored;
    while(1)
    {
        mutex_lock(&shared_counter_mutex);
        shared_counter++;
        //printf("%zu\n", shared_counter);
        if (shared_counter > COUNTER_TARGET)
            break;
        mutex_unlock(&shared_counter_mutex);
    }
    mutex_unlock(&shared_counter_mutex);
    return NULL;
}

int main(int argc, const char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Supply number of threads as cmdline arg\n");
        return EXIT_FAILURE;
    }

    if (mutex_lib_init() != MUTEX_OK) {
        fprintf(stderr, "Can't initialize mutex library\n");
        return EXIT_FAILURE;
    }
    mutex_init(&shared_counter_mutex);

    size_t workers_num = 2;
    size_t workers_ix = 0;
    sscanf(argv[1], "%zu", &workers_num);
    pthread_attr_t thread_attrs;
    pthread_attr_init(&thread_attrs);
    pthread_t *threads =
        (pthread_t*)malloc(sizeof(pthread_t) * workers_num);

    for (workers_ix = 0; workers_ix < workers_num; ++workers_ix)
    {
        pthread_create(&threads[workers_ix], &thread_attrs,
                &bench_thread_func, NULL);
    }

    for (workers_ix = 0; workers_ix < workers_num; ++workers_ix)
    {
        pthread_join(threads[workers_ix], NULL);
    }

    free(threads);
    mutex_lib_deinit();

    return EXIT_SUCCESS;
}
