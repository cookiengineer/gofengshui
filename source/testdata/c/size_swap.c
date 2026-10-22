#include "gfs_harness.h"

int main(void)
{
	char *a = malloc(0x30);
	char *b = malloc(0x30);
	if (!a || !b)
		return 1;

	/* Replace b's size with another valid-looking chunk size. */
	*(uint64_t *)(void *)(b - 8) = 0x51;
	free(b);
	free(a);
	return 0;
}
