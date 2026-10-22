#include "gfs_harness.h"

int main(void)
{
	char *p = malloc(64);
	if (!p)
		return 1;
	for (int i = 0; i < 64; i++) {
		size_t size = 64 + (size_t)(i % 8) * 64;
		char *q = realloc(p, size);
		if (!q) {
			free(p);
			return 1;
		}
		p = q;
		memset(p, 'A' + (i % 26), size);
	}
	free(p);
	return 0;
}
