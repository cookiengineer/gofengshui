#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/types.h>
#include <unistd.h>

#include "gfs_harness.h"

int main(void)
{
	char *path = malloc(64);
	if (!path)
		return 1;
	memcpy(path, "/etc/hostname", sizeof("/etc/hostname"));
	free(path);
	int fd = openat(AT_FDCWD, path, O_RDONLY);
	if (fd >= 0)
		close(fd);

	char *epath = malloc(64);
	if (epath) {
		memcpy(epath, "/nonexistent/gfs", sizeof("/nonexistent/gfs"));
		free(epath);
		char *argv[] = {"gfs", NULL};
		(void)execve(epath, argv, NULL);
	}

	int in = open("/dev/zero", O_RDONLY);
	int out = open("/dev/null", O_WRONLY);
	if (in >= 0 && out >= 0) {
		off_t *off = malloc(sizeof(*off));
		if (off) {
			*off = 0;
			free(off);
			(void)sendfile(out, in, off, 16);
		}
	}

	int p[2];
	if (pipe(p) == 0) {
		off_t *off = malloc(sizeof(*off));
		if (off) {
			*off = 0;
			free(off);
			(void)splice(in >= 0 ? in : p[0], off, p[1], NULL, 16, 0);
		}
	}

	if (out >= 0)
		close(out);
	if (in >= 0)
		close(in);
	_exit(0);
}
