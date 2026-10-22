#include "gfs_harness.h"

int main(void)
{
	char *p = malloc(16);
	if (!p)
		return 1;
	memset(p, 'A', 16);
	ssize_t n = write(STDOUT_FILENO, p, 64);
	free(p);
	return n < 0;
}
