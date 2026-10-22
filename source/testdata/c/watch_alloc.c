#include "gfs_harness.h"

int main(void)
{
	volatile unsigned char *p = malloc(0x40);
	if (!p)
		return 1;
	p[0] = 'A';

	FILE *f = fopen("/tmp/watch_alloc.addr", "w");
	if (f) {
		fprintf(f, "%lu\n", (unsigned long)(uintptr_t)p);
		fclose(f);
	}
	for (int i = 0; i < 500; i++) {
		if (access("/tmp/watch_alloc.release", F_OK) == 0)
			break;
		usleep(10000);
	}
	p[0] = 'B';
	sleep(1);
	free((void *)p);
	return 0;
}
