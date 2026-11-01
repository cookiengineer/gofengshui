#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "gfs_harness.h"

/*
 * Keep a stable mixed-size live set long enough to learn a baseline, then
 * shift the heap composition with a same-size live spray and reuse churn.
 */
int main(void)
{
	void *baseline[128];
	for (int i = 0; i < 128; i++) {
		size_t size = i < 64 ? 0x30 : 0x90;
		baseline[i] = malloc(size);
		if (!baseline[i])
			return 1;
		memset(baseline[i], 'B', size);
	}

	for (int i = 0; i < 256; i++) {
		void *a = malloc(0x30);
		void *b = malloc(0x90);
		if (!a || !b)
			return 1;
		memset(a, 'A', 0x30);
		memset(b, 'C', 0x90);
		free(a);
		free(b);
	}
	usleep(50000);

	void *keep[1024];
	for (int i = 0; i < 1024; i++) {
		keep[i] = malloc(0x90);
		if (!keep[i])
			return 1;
		memset(keep[i], 'S', 0x90);
	}

	for (int i = 0; i < 512; i++) {
		void *p = malloc(0x90);
		if (!p)
			return 1;
		free(p);
	}
	usleep(50000);

	for (int i = 0; i < 1024; i += 2)
		free(keep[i]);
	for (int i = 0; i < 512; i++) {
		void *p = malloc(0x90);
		if (!p)
			return 1;
		free(p);
	}
	usleep(100000);

	for (int i = 0; i < 128; i++)
		free(baseline[i]);
	return 0;
}
