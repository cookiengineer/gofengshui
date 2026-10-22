#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "gfs_harness.h"

int main(void)
{
	char exe[512];
	char plugin[600];
	ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
	if (n <= 0)
		return 1;
	exe[n] = 0;
	char *slash = strrchr(exe, '/');
	if (!slash)
		return 1;
	*slash = 0;
	snprintf(plugin, sizeof(plugin), "%s/libgfsplugin.so", exe);

	void *h = dlopen(plugin, RTLD_NOW);
	if (!h)
		return 1;
	void *(*alloc_fn)(unsigned long) = dlsym(h, "gfs_plugin_alloc");
	void (*free_fn)(void *) = dlsym(h, "gfs_plugin_free");
	if (!alloc_fn || !free_fn)
		return 1;

	for (int i = 0; i < 16; i++) {
		void *p = alloc_fn(0x120 + (unsigned long)i * 0x10);
		if (!p)
			return 1;
		memset(p, 'P', 0x120);
		free_fn(p);
	}

	FILE *f = fopen("/tmp/dlopen_alloc.ready", "w");
	if (f) {
		fprintf(f, "ready\n");
		fclose(f);
	}
	for (int i = 0; i < 300; i++) {
		if (access("/tmp/dlopen_alloc.release", F_OK) == 0)
			break;
		usleep(10000);
	}

	void *live = alloc_fn(0x1234);
	if (!live)
		return 1;
	memset(live, 'L', 0x1234);
	f = fopen("/tmp/dlopen_alloc.ptr", "w");
	if (f) {
		fprintf(f, "%lu\n", (unsigned long)(uintptr_t)live);
		fclose(f);
	}
	sleep(3);
	dlclose(h);
	return 0;
}
