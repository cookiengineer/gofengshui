#include "gfs_harness.h"

int main(int argc, char **argv)
{
	volatile unsigned char *p = malloc(0x40);
	if (!p)
		return 1;
	p[0] = 'A';

	FILE *f = fopen("/tmp/uaf_direct.addr", "w");
	if (f) {
		fprintf(f, "%lu\n", (unsigned long)(uintptr_t)p);
		fclose(f);
	}
	if (argc > 1 && strcmp(argv[1], "wait") == 0) {
		for (int i = 0; i < 500; i++) {
			if (access("/tmp/uaf_direct.release", F_OK) == 0)
				break;
			usleep(10000);
		}
	}
	free((void *)p);
	usleep(200000);
	p[0] = 'X';
	sleep(1);
	return 0;
}
