#include "gfs_harness.h"
#include <pthread.h>

static void *worker(void *arg)
{
	long id = (long)arg;
	void *a = malloc(0x50);
	void *b = malloc(0x90);
	char path[64];

	snprintf(path, sizeof(path), "/tmp/arena_backfill.%ld.addrs", id);
	FILE *f = fopen(path, "w");
	if (f) {
		fprintf(f, "%lu\n%lu\n", (unsigned long)a, (unsigned long)b);
		fclose(f);
	}
	sleep(3);
	free(a);
	free(b);
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
