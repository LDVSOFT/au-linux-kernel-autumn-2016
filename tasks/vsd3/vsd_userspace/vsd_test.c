#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "vsd_device.h"

#define TEST(assertion) \
    if (!(assertion)) { \
        fprintf(stderr, "%s %d\n", __FILE__, __LINE__); \
        perror("Test failed"); \
        abort(); \
    }

int main()
{
    TEST(!vsd_init());

    size_t vsd_size = 0;
    TEST(!vsd_get_size(&vsd_size));
    TEST(vsd_set_size(vsd_size * 2));

    unsigned char *vsd_w_buf = malloc(vsd_size);
    unsigned char *vsd_r_buf = calloc(1, vsd_size);
    size_t i = 0;
    for (; i < vsd_size; ++i) {
        vsd_w_buf[i] = i % 255;
    }

    // Check rw
    TEST(vsd_write(vsd_w_buf, vsd_size) == vsd_size);
    TEST(vsd_read(vsd_r_buf, vsd_size) == vsd_size);
    TEST(!memcmp(vsd_w_buf, vsd_r_buf, vsd_size));

    // Check ioctls
    size_t vsd_new_size = vsd_size / 2;
    TEST(!vsd_set_size(vsd_new_size));
    TEST(!vsd_get_size(&vsd_size));
    TEST(vsd_size == vsd_new_size);

    TEST(!vsd_deinit());
    free(vsd_w_buf);
    free(vsd_r_buf);
    printf("Ok\n");
    return 0;
}
