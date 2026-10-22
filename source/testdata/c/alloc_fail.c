#include "gfs_harness.h"
#include <sys/mman.h>

int main(void)
{
	void *p = malloc((size_t)-1);
	void *m = mmap(NULL, (size_t)1 << 48, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p)
		free(p);
	if (m != MAP_FAILED)
		munmap(m, (size_t)1 << 48);
	return 0;
}
