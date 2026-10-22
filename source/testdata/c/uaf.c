#include "gfs_harness.h"

int main(void)
{
	char *p = malloc(64);
	if (!p)
		return 1;
	memcpy(p, "gfs-uaf", 8);
	free(p);
	ssize_t n = write(STDOUT_FILENO, p, 16);
	return n < 0;
}
