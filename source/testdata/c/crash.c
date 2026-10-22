#include "gfs_harness.h"

int main(void)
{
	volatile int *p = (volatile int *)0;
	*p = 0x41414141;
	return 0;
}
