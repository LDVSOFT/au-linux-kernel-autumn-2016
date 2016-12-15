#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include "vsd_device.h"

#define LOCAL_DEBUG 0
#define VSD_DEV_QUEUE_SIZE 10

#define TEST(assertion) \
    if (!(assertion)) { \
        fprintf(stderr, "%s %d\n", __FILE__, __LINE__); \
        perror("Test failed"); \
        abort(); \
    }

static size_t vsd_size = 0;

static void test_size_set(size_t new_size)
{
    TEST(!vsd_set_size(new_size));
    TEST(!vsd_get_size(&vsd_size));
    TEST(vsd_size == new_size);
}

static void test_blocking_rw(void)
{
    unsigned char *vsd_w_buf = malloc(vsd_size);
    unsigned char *vsd_r_buf = calloc(1, vsd_size);
    size_t i = 0;
    for (; i < vsd_size; ++i)
        vsd_w_buf[i] = i % 255;

    // Check rw
    TEST(!vsd_set_blocking());
    TEST(vsd_write(vsd_w_buf, vsd_size, 0) == vsd_size);
    TEST(vsd_read(vsd_r_buf, vsd_size, 0) == vsd_size);
#if LOCAL_DEBUG
    for (i = 0; i < vsd_size; ++i)
        printf("%u ", (unsigned int)vsd_w_buf[i]);
    printf("\n");
    for (i = 0; i < vsd_size; ++i)
        printf("%u ", (unsigned int)vsd_r_buf[i]);
    printf("\n");
#endif
    TEST(!memcmp(vsd_w_buf, vsd_r_buf, vsd_size));

    free(vsd_w_buf);
    free(vsd_r_buf);
}

static void test_blocking_queue_overflow(void)
{
    // Check that we can perform > 10 (vsd max queue len)
    // blocking request simultaneously.
    // Our device is slow so we'll fill the queue before it completes
    // its first cmd.
    size_t i;
    unsigned char *vsd_w_buf = malloc(vsd_size);
    unsigned char *vsd_r_buf = calloc(1, vsd_size);

    TEST(!vsd_set_blocking());
    const size_t FORKS_COUNT = VSD_DEV_QUEUE_SIZE * 3 / 2;
    for (i = 0; i < FORKS_COUNT; ++i) {
        if (fork()) 
            continue;
        // We're in forked child
        TEST(vsd_write(vsd_w_buf, vsd_size, 0) == vsd_size);
        TEST(vsd_read(vsd_r_buf, vsd_size, 0) == vsd_size);
        exit(0);
    }

    i = 0;
    while (i < FORKS_COUNT) {
        int status;
        wait(&status);
        if (WIFEXITED(status)) {
            TEST(WEXITSTATUS(status) == 0);
            ++i;
        }
    }

    free(vsd_w_buf);
    free(vsd_r_buf);
}

static void test_nonblocking_w(void)
{
    unsigned char *vsd_w_buf = malloc(vsd_size);
    unsigned char *vsd_r_buf = calloc(1, vsd_size);
    const size_t async_chunk_size = vsd_size / VSD_DEV_QUEUE_SIZE;
    size_t i = 0;

    for (; i < vsd_size; ++i)
        vsd_w_buf[i] = (i + 2) % 255;

    TEST(!vsd_set_nonblocking());
   
    // Write VSD_DEV_QUEUE_SIZE chunks in non blocking mode
    for(i = 0; i < VSD_DEV_QUEUE_SIZE; ++i) {
        const size_t chunk_offset = i * async_chunk_size; 
        unsigned char *chunk = vsd_w_buf + chunk_offset;
        TEST(vsd_write(chunk, async_chunk_size, (off_t)chunk_offset) == async_chunk_size);
    }
    // Queue is full. Next should block.
    // This depends on device speed
    TEST(vsd_write(vsd_w_buf, 1, 0) == -1);
    TEST(errno == EAGAIN);

    // Check that non blocking writes has completed ok
    TEST(!vsd_set_blocking());
    TEST(vsd_read(vsd_r_buf, vsd_size, 0) == vsd_size);
    TEST(!memcmp(vsd_w_buf, vsd_r_buf,
                async_chunk_size * VSD_DEV_QUEUE_SIZE));

    free(vsd_w_buf);
    free(vsd_r_buf);
}

static void test_vsd_poll(void)
{
    char zeroes[10] = {};

    TEST(!vsd_set_nonblocking());

    while (1) {
        ssize_t ret = vsd_write(zeroes, sizeof(zeroes), 0);
        if ((ret < 0) && (errno == EAGAIN)) {
            break;
        }
    }

    TEST(!vsd_wait_nonblock_write());
    TEST(vsd_write(zeroes, sizeof(zeroes), 0) == sizeof(zeroes));
}

static void print_test_stage_ok(void)
{
    static size_t stage = 0;
    printf("test stage %zu ok\n", stage++);
}

int main()
{
    size_t vsd_initial_size = 0;

    TEST(!vsd_init());
    TEST(!vsd_get_size(&vsd_initial_size));
    test_size_set(vsd_initial_size);
    test_blocking_rw();
    print_test_stage_ok();

    test_blocking_queue_overflow();
    test_nonblocking_w();
    print_test_stage_ok();

    test_size_set(vsd_initial_size / 2);
    test_blocking_rw();
    print_test_stage_ok();

    test_size_set(vsd_initial_size / 4);
    test_blocking_rw();
    print_test_stage_ok();

    test_vsd_poll();
    print_test_stage_ok();

    TEST(!vsd_deinit());
    printf("Test ok\n");
    return 0;
}
