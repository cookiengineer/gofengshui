#include <gnu/libc-version.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "gfs_harness.h"

/*
 * Simulate a tcache poisoning write: two same-size chunks are freed, then the
 * deeper chunk's encoded next pointer is overwritten with a bogus target. The
 * agent should notice the corrupt link when that chunk is popped from tcache.
 */
int main(void)
{
	const size_t request = 0x38;
	unsigned char *a = malloc(request);
	unsigned char *b = malloc(request);

	if (!a || !b)
		return 1;
	memset(a, 'A', request);
	memset(b, 'B', request);

	free(a);
	free(b);

	uint64_t target = 0x414141414141ULL;
	uint64_t encoded = target;

	int major = 0, minor = 0;
	const char *version = gnu_get_libc_version();
	if (version)
		sscanf(version, "%d.%d", &major, &minor);
	if (major > 2 || (major == 2 && minor >= 32))
		encoded = target ^ ((uint64_t)(uintptr_t)a >> 12);

	*(uint64_t *)(void *)a = encoded;

	/* Pop b, then a. The second pop installs the poisoned head. */
	void *c = malloc(request);
	void *d = malloc(request);
	(void)c;
	(void)d;

	_exit(0);
}
