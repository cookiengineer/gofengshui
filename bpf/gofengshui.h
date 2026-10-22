#ifndef GFS_BPF_H
#define GFS_BPF_H

#define GFS_COMM_LEN 16
#define GFS_MAX_STACK_DEPTH 32

enum gfs_event_type {
	GFS_EV_ALLOC = 1,
	GFS_EV_FREE = 2,
	GFS_EV_DOUBLE_FREE = 3,
	GFS_EV_INVALID_FREE = 4,
	GFS_EV_MMAP = 5,
	GFS_EV_MUNMAP = 6,
	GFS_EV_BRK = 7,
	GFS_EV_MREMAP = 8,
	GFS_EV_MEM_ACCESS = 9,
	GFS_EV_SYSCALL_RET = 10,
	GFS_EV_ALLOC_FAIL = 11,
	GFS_EV_STAT = 12,
	GFS_EV_OOM = 13,
};

enum gfs_alloc_op {
	GFS_OP_MALLOC = 1,
	GFS_OP_CALLOC = 2,
	GFS_OP_REALLOC = 3,
	GFS_OP_FREE = 4,
	GFS_OP_ALIGNED = 5,
	GFS_OP_NEW = 6,
	GFS_OP_DELETE = 7,
};

#define GFS_F_HEAP     (1U << 0)
#define GFS_F_SYSCALL  (1U << 1)
#define GFS_F_UAF      (1U << 2)
#define GFS_F_STACKS   (1U << 3)
#define GFS_F_DETECT   (1U << 4)

#define GFS_AF_UNKNOWN    (1U << 0)
#define GFS_AF_LINK       (1U << 1)
#define GFS_AF_METADATA   (1U << 2)
#define GFS_AF_NEXT       (1U << 3)

/*
 * Default x86_64 tcache small-bin chunk-size ceiling. Glibc 2.42+ still uses
 * 0x410 as the default tcache_max_bytes; large tcache bins are tunable and are
 * observation-only in userspace.
 */
#define GFS_TCACHE_MAX_CHUNK 0x410

/* x86_64 syscall numbers */
#define GFS_NR_READ     0
#define GFS_NR_WRITE    1
#define GFS_NR_MMAP     9
#define GFS_NR_MUNMAP   11
#define GFS_NR_BRK      12
#define GFS_NR_PREAD64  17
#define GFS_NR_PWRITE64 18
#define GFS_NR_MREMAP   25
#define GFS_NR_SENDFILE 40
#define GFS_NR_SENDTO   44
#define GFS_NR_RECVFROM 45
#define GFS_NR_EXECVE   59
#define GFS_NR_OPENAT   257
#define GFS_NR_SPLICE   275

struct gfs_config {
	__u64 cgroup_id;
	__u32 pid;
	__u32 flags;
	__u32 sample;
	__u32 agent_pid;
};

struct gfs_pending {
	__u64 size;
	__u64 ts;
	__u64 caller;
	__u64 old_ptr;
	__u32 op;
	__u32 tid;
	__u32 pad;
};

struct gfs_pending_sys {
	__u64 ts;
	__u32 id;
	__u32 tid;
};

struct gfs_alloc {
	__u64 addr;
	__u64 req_size;
	__u64 chunk_size;
	__u64 ts;
	__u64 stack_id;
	__u64 caller;
	__u32 tid;
	__u32 op;
	__u32 state;
	__u32 pad;
};

struct gfs_tomb {
	__u64 addr;
	__u64 size;
	__u64 ts;
	__u32 tid;
	__u32 gen;
};

struct gfs_stats {
	__u64 events;
	__u64 drops;
	__u64 allocs;
	__u64 frees;
	__u64 checks;
};

struct gfs_event {
	__u64 ts;
	__u64 addr;
	__u64 size;
	__u64 req_size;
	__u64 caller;
	__u64 stack_id;
	__u64 arg1;
	__u64 arg2;
	__u64 aux1;
	__u64 aux2;
	__u32 type;
	__u32 pid;
	__u32 tid;
	__u32 flags;
	char comm[GFS_COMM_LEN];
	__u32 pad;
} __attribute__((packed));

#endif
