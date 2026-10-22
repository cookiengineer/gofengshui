#include "gfs_harness.h"

/*
 * Deliberately vulnerable: no stack protector, fixed 128-byte buffer.
 * The chain is:
 *   saved RIP -> gfs_pop_rdi_ret -> 0x4141 -> gfs_sink
 */
GFS_NOINLINE void gfs_vuln(void *src, size_t len)
{
	char buf[128];
	memcpy(buf, src, len);
	__asm__ __volatile__("" : : "r"(buf) : "memory");
}

int main(void)
{
	unsigned char payload[160];
	memset(payload, 'A', sizeof(payload));

	uint64_t *words = (uint64_t *)payload;
	words[16] = 0x4242424242424242ULL;       /* saved rbp */
	words[17] = (uint64_t)(uintptr_t)gfs_pop_rdi_ret;
	words[18] = 0x4141;
	words[19] = (uint64_t)(uintptr_t)gfs_sink;

	gfs_vuln(payload, sizeof(payload));
	return 0;
}
