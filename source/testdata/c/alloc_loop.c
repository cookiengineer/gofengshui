#include "gfs_harness.h"

int main(void)
{
	for (int i = 0; i < 2000; i++) {
		size_t size = 16 + (size_t)(i % 16) * 16;
		char *p = malloc(size);
		if (!p)
			return 1;
		memset(p, (int)(i & 0xff), size);
		free(p);
	}
	return 0;
}
