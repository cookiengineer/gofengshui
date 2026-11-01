#include "gfs_harness.h"

#include <time.h>

static int64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int main(void)
{
	void *batch[64];
	int64_t start = now_ms();
	int64_t deadline = start + 1500;
	unsigned long iterations = 0;

	while (now_ms() < deadline) {
		for (int i = 0; i < 64; i++) {
			size_t size = 0x30 + (size_t)(i % 4) * 0x30;
			batch[i] = malloc(size);
			if (batch[i])
				memset(batch[i], (iterations + i) & 0xff, size);
		}
		for (int i = 0; i < 64; i++)
			free(batch[i]);
		iterations++;
	}

	printf("elapsed_ms=%lld iterations=%lu\n",
	       (long long)(now_ms() - start), iterations);
	return 0;
}
