#include "gfs_harness.h"

int main(void)
{
	void *a = malloc(0x30);
	void *b = malloc(0x50);
	void *c = malloc(0x90);
	FILE *f = fopen("/tmp/backfill.addrs", "w");
	if (f) {
		fprintf(f, "%lu\n%lu\n%lu\n", (unsigned long)a, (unsigned long)b, (unsigned long)c);
		fclose(f);
	}
	sleep(2);
	free(a);
	free(b);
	free(c);
	return 0;
}
