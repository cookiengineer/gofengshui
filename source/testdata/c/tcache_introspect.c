#include "gfs_harness.h"

/*
 * Fill the main thread's tcache and spill the oldest frees into a smallbin.
 * Addresses are written out so the attach-side test can verify the observed
 * LIFO order and size class.
 */
int main(void)
{
	enum { N = 20 };
	char *p[N];

	for (int i = 0; i < N; i++) {
		p[i] = malloc(24);
		if (!p[i])
			return 1;
		memset(p[i], 'A' + (i % 26), 24);
	}
	for (int i = 0; i < N; i++)
		free(p[i]);

	FILE *f = fopen("/tmp/tcache_introspect.addrs", "w");
	if (!f)
		return 1;
	for (int i = 0; i < N; i++)
		fprintf(f, "%llu\n", (unsigned long long)(uintptr_t)p[i]);
	fclose(f);

	sleep(30);
	return 0;
}
