#include "gfs_harness.h"

/*
 * Allocate without freeing. Used to verify allocator-profile plumbing through
 * the eBPF allocator hooks without exercising tcache free-list logic, which
 * would depend on the (possibly overridden) profile matching the real libc.
 */
int main(void)
{
	char *p[8];

	for (int i = 0; i < 8; i++) {
		p[i] = malloc(64 + (size_t)i * 16);
		if (!p[i])
			return 1;
		memset(p[i], 'A' + i, 64 + (size_t)i * 16);
	}
	return 0;
}
