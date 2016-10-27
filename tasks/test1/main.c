#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

int main() {
	size_t available = 0;
	size_t page_size = sysconf(_SC_PAGE_SIZE);
	for (int level = 50; level >= 0; --level) {
		size_t size = ((size_t)1) << level;
		if (size < page_size) {
			break;
		}
		while (1) {
			ssize_t p = mmap(NULL, size, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			if (p == -1) {
				break;
			}
			available += size;
		}
	}
	printf("VM I just ate: %zu\n", available);
	return 0;
}
