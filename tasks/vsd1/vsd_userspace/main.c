#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include "vsd_ioctl.h"

const char filename[] = "/dev/vsd";

void print_info() {
    fprintf(stderr, "Usage: vsd_userspace (size_get | size_set <bytes>)\n");
}

int main(int argc, const char **argv) {
    if (argc < 2) {
        fprintf(stderr, "No action given.\n");
        print_info();
        return EXIT_FAILURE;
    }
    const char *action = argv[1];
    if (strcmp(action, "size_set") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Wrong argument count.\n");
            print_info();
            return EXIT_FAILURE;
        }
        int new_size = atoi(argv[2]);

        int fd = open(filename, 0);
        if (fd == -1) {
            fprintf(stderr, "Failed to open file: errno=%d.\n", errno);
            return EXIT_FAILURE;
        }

        vsd_ioctl_set_size_arg_t arg;
        arg.size = new_size;
        int res = ioctl(fd, VSD_IOCTL_SET_SIZE, &arg);
        if (res == -1)
            fprintf(stderr, "Failed to set size: errno=%d.\n", errno);

        close(fd);
        return (res != -1) ? EXIT_SUCCESS : EXIT_FAILURE;
        return (res != -1) ? 0 : 2;
    }
    if (strcmp(action, "size_get") == 0) {
        if (argc != 2) {
            fprintf(stderr, "Wrong argument count.\n");
            print_info();
            return EXIT_FAILURE;
        }

        int fd = open(filename, 0);
        if (fd == -1) {
            fprintf(stderr, "Failed to open file: errno=%d.\n", errno);
            return EXIT_FAILURE;
        }

        vsd_ioctl_get_size_arg_t arg;
        int res = ioctl(fd, VSD_IOCTL_GET_SIZE, &arg);
        if (res == -1)
            fprintf(stderr, "Failed to set size: errno=%d.\n", errno);
        else
            printf("%lu\n", arg.size);

        close(fd);
        return (res != -1) ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    fprintf(stderr, "Unknown action.\n");
    return EXIT_FAILURE;
}
