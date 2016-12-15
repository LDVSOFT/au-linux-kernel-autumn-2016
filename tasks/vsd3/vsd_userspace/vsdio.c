#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vsd_device.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Supply command name (size_set|size_get)\n");
        return EXIT_FAILURE;
    }
    if (vsd_init()) {
        perror("Couldn't init vsd device\n");
        return EXIT_FAILURE;
    }

    if (!strcmp(argv[1], "size_get")) {
        size_t size = 0;
        int ret = vsd_get_size(&size);
        if (!ret)
            printf("Size is %zu\n", size);
        else
            fprintf(stderr,
                    "Couldn't get vsd size error code: %d\n", ret);
    } else if (!strcmp(argv[1], "size_set")) {
        if (argc > 2) {
            size_t size = 0;
            sscanf(argv[2], "%zu", &size);
            int ret = vsd_set_size(size);
            if (ret) {
                fprintf(stderr,
                        "Couldn't set vsd size error code: %d\n", ret);
            }
        } else {
            fprintf(stderr, "Supply new size\n");
        }
    } else {
        fprintf(stderr, "Invalid command\n");
    }
    vsd_deinit();
    return EXIT_SUCCESS;
}
