#ifndef GFS_HARNESS_H
#define GFS_HARNESS_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__GNUC__)
#define GFS_NOINLINE __attribute__((noinline))
#define GFS_USED __attribute__((used, visibility("default")))
#else
#define GFS_NOINLINE
#define GFS_USED
#endif

GFS_NOINLINE GFS_USED void gfs_sink(uint64_t a, uint64_t b, uint64_t c)
{
	volatile uint64_t x = a ^ b ^ c;
	(void)x;
}

#if defined(__x86_64__)

void gfs_pop_rdi_ret(void);
void gfs_ret(void);

/*
 * Top-level assembly avoids the compiler-emitted prologue. A normal C
 * function would push rbp before the pop, corrupting the ROP chain.
 */
__asm__(
	".text\n"
	".globl gfs_pop_rdi_ret\n"
	".type gfs_pop_rdi_ret,@function\n"
	"gfs_pop_rdi_ret:\n"
	"\tpop %rdi\n"
	"\tret\n"
	".size gfs_pop_rdi_ret, .-gfs_pop_rdi_ret\n"
	".globl gfs_ret\n"
	".type gfs_ret,@function\n"
	"gfs_ret:\n"
	"\tret\n"
	".size gfs_ret, .-gfs_ret\n"
);

#else

GFS_NOINLINE GFS_USED void gfs_pop_rdi_ret(void) {}
GFS_NOINLINE GFS_USED void gfs_ret(void) {}

#endif

#endif
