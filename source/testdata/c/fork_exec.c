#include "gfs_harness.h"
#include <sys/wait.h>

static void child_work(void)
{
	for (int i = 0; i < 200; i++) {
		char *p = malloc(64 + (size_t)(i % 4) * 16);
		if (!p)
			return;
		memset(p, i, 64);
		free(p);
	}
}

int main(int argc, char **argv)
{
	if (argc > 1 && strcmp(argv[1], "child") == 0) {
		child_work();
		return 0;
	}

	/* Parent allocations make the follow assertion distinguish parent+child. */
	child_work();
	pid_t pid = fork();
	if (pid < 0)
		return 1;
	if (pid == 0) {
		char *args[] = {argv[0], "child", NULL};
		execv(argv[0], args);
		_exit(127);
	}
	int status = 0;
	waitpid(pid, &status, 0);
	return 0;
}
