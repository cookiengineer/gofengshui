#include "gfs_harness.h"
#include <pthread.h>

/*
 * Each worker fills its own tcache and reports the free order. Attach-side
 * introspection should recover one tcache snapshot per stopped thread.
 */
static void *worker(void *arg)
{
	long id = (long)arg;
	enum { N = 8 };
	char *p[N];
	char path[64];

	for (int i = 0; i < N; i++) {
		p[i] = malloc(24);
		if (!p[i])
			return NULL;
	}
	for (int i = 0; i < N; i++)
		free(p[i]);

	snprintf(path, sizeof(path), "/tmp/tcache_threads.%ld.addrs", id);
	FILE *f = fopen(path, "w");
	if (f) {
		for (int i = 0; i < N; i++)
			fprintf(f, "%llu\n", (unsigned long long)(uintptr_t)p[i]);
		fclose(f);
	}
	sleep(10);
	return NULL;
}

int main(void)
{
	pthread_t threads[2];
	for (long i = 0; i < 2; i++) {
		if (pthread_create(&threads[i], NULL, worker, (void *)i) != 0)
			return 1;
	}
	for (int i = 0; i < 2; i++)
		pthread_join(threads[i], NULL);
	return 0;
}
