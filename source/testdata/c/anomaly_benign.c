#include "gfs_harness.h"

#include <pthread.h>
#include <time.h>

static int64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void run_steady(int64_t deadline)
{
	void *live[256];
	for (int i = 0; i < 256; i++) {
		size_t size = i < 128 ? 0x30 : 0x90;
		live[i] = malloc(size);
		if (!live[i])
			return;
		memset(live[i], 'A' + (i % 26), size);
	}
	int i = 0;
	while (now_ms() < deadline) {
		size_t size = (i % 2) == 0 ? 0x30 : 0x90;
		void *p = malloc(size);
		if (!p)
			break;
		memset(p, 'a' + (i % 26), size);
		free(p);
		void *q = malloc(size);
		if (q) {
			memset(q, 'a' + (i % 26), size);
			free(q);
		}
		i++;
		usleep(1000);
	}
	(void)live;
}

static void run_churn(int64_t deadline)
{
	int i = 0;
	while (now_ms() < deadline) {
		size_t size = 16 + (size_t)(i % 8) * 16;
		void *a = malloc(size);
		void *b = malloc(size * 2);
		if (!a || !b) {
			free(a);
			free(b);
			break;
		}
		memset(a, i & 0xff, size);
		memset(b, (i + 1) & 0xff, size * 2);
		free(a);
		free(b);
		i++;
		usleep(200);
	}
}

struct worker_arg {
	int64_t deadline;
	long id;
};

static void *worker(void *arg)
{
	struct worker_arg *wa = arg;
	int i = 0;
	while (now_ms() < wa->deadline) {
		size_t size = 32 + (size_t)(i % 8) * 16;
		char *p = malloc(size);
		if (!p)
			break;
		memset(p, (i + (int)wa->id) & 0xff, size);
		free(p);
		i++;
		usleep(1000);
	}
	return NULL;
}

static void run_threads(int64_t deadline)
{
	pthread_t threads[4];
	struct worker_arg args[4];
	for (long i = 0; i < 4; i++) {
		args[i].deadline = deadline;
		args[i].id = i;
		pthread_create(&threads[i], NULL, worker, &args[i]);
	}
	for (int i = 0; i < 4; i++)
		pthread_join(threads[i], NULL);
}

static void run_realloc(int64_t deadline)
{
	char *p = malloc(64);
	if (!p)
		return;
	memset(p, 'R', 64);
	int i = 0;
	while (now_ms() < deadline) {
		size_t size = 64 + (size_t)(i % 8) * 64;
		char *q = realloc(p, size);
		if (!q)
			break;
		p = q;
		memset(p, 'A' + (i % 26), size);
		i++;
		usleep(500);
	}
	free(p);
}

static void run_burst(int64_t deadline)
{
	void *batch[64];
	while (now_ms() < deadline) {
		for (int i = 0; i < 64; i++) {
			size_t size = 0x30 + (size_t)(i % 4) * 0x30;
			batch[i] = malloc(size);
			if (batch[i])
				memset(batch[i], 'B', size);
		}
		usleep(2000);
		for (int i = 0; i < 64; i++)
			free(batch[i]);
		usleep(2000);
	}
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "steady";
	int64_t deadline = now_ms() + 2000;

	if (strcmp(mode, "steady") == 0)
		run_steady(deadline);
	else if (strcmp(mode, "churn") == 0)
		run_churn(deadline);
	else if (strcmp(mode, "threads") == 0)
		run_threads(deadline);
	else if (strcmp(mode, "realloc") == 0)
		run_realloc(deadline);
	else if (strcmp(mode, "burst") == 0)
		run_burst(deadline);
	else
		return 2;
	return 0;
}
