#include "gfs_harness.h"
#include <pthread.h>

static void *worker(void *arg)
{
	long id = (long)arg;
	for (int i = 0; i < 2000; i++) {
		size_t size = 32 + (size_t)((i + (int)id) % 8) * 16;
		char *p = malloc(size);
		if (!p)
			return NULL;
		memset(p, (int)(i + id), size);
		free(p);
		usleep(500);
	}
	return NULL;
}

int main(void)
{
	pthread_t threads[4];
	for (long i = 0; i < 4; i++) {
		if (pthread_create(&threads[i], NULL, worker, (void *)i) != 0)
			return 1;
	}
	for (int i = 0; i < 4; i++)
		pthread_join(threads[i], NULL);
	return 0;
}
