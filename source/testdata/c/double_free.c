#include "gfs_harness.h"

int main(void)
{
	void *p = malloc(64);
	if (!p)
		return 1;
	free(p);
	free(p);
	return 0;
}
