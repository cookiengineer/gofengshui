#include <stddef.h>
#include <stdlib.h>

void *gfs_plugin_alloc(unsigned long size)
{
	return malloc((size_t)size);
}

void gfs_plugin_free(void *ptr)
{
	free(ptr);
}
