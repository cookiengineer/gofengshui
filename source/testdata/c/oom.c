#include "gfs_harness.h"

int main(void)
{
	FILE *f = fopen("/proc/self/oom_score_adj", "w");
	if (f) {
		fprintf(f, "1000\n");
		fclose(f);
	}
	int adj = -1;
	f = fopen("/proc/self/oom_score_adj", "r");
	if (f) {
		if (fscanf(f, "%d", &adj) != 1)
			adj = -1;
		fclose(f);
	}
	if (adj != 1000)
		return 2;
	const size_t chunk = 32 * 1024 * 1024;
	for (int i = 0; i < 512; i++) {
		char *p = malloc(chunk);
		if (!p)
			return 1;
		memset(p, 0x5a, chunk);
	}
	return 0;
}
