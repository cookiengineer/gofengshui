#include "gfs_harness.h"

int main(void)
{
	char *a = malloc(0x30);
	char *b = malloc(0x30);
	if (!a || !b)
		return 1;

	/* Corrupt b's chunk size field before free() validates it. */
	*(uint64_t *)(void *)(b - 8) = 0x39;
	free(b);
	free(a);
	return 0;
}
