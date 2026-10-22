#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/bpf.h>
#include "vmlinux_min.h"
#define __VMLINUX_H__ 1
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "gofengshui.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct gfs_config);
} config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct gfs_alloc);
} allocs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct gfs_tomb);
} tombstones SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, struct gfs_pending);
} pending SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, struct gfs_pending_sys);
} pending_sys SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 16384);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, GFS_MAX_STACK_DEPTH * sizeof(__u64));
} stacks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct gfs_stats);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline struct gfs_config *gfs_cfg(void)
{
	__u32 key = 0;
	return bpf_map_lookup_elem(&config, &key);
}

static __always_inline int gfs_allowed(struct gfs_config *cfg)
{
	if (!cfg)
		return 0;

	if (cfg->cgroup_id) {
		__u64 id = bpf_get_current_cgroup_id();
		if (cfg->cgroup_id != id)
			return 0;
	}

	if (cfg->pid) {
		__u32 pid = bpf_get_current_pid_tgid() >> 32;
		if (cfg->pid != pid)
			return 0;
	}

	return 1;
}

static __always_inline void gfs_emit(struct gfs_event *ev)
{
	__u32 key = 0;
	struct gfs_stats *st = bpf_map_lookup_elem(&stats, &key);

	ev->pid = bpf_get_current_pid_tgid() >> 32;
	ev->tid = bpf_get_current_pid_tgid();
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

	if (st)
		st->events++;

	if (bpf_ringbuf_output(&events, ev, sizeof(*ev), 0) && st)
		st->drops++;
}

static __always_inline void gfs_init(struct gfs_event *ev, __u32 type)
{
	__builtin_memset(ev, 0, sizeof(*ev));
	ev->ts = bpf_ktime_get_ns();
	ev->type = type;
}

static __always_inline __u64 gfs_chunk_size(__u64 addr, __u64 req)
{
	__u64 hdr = 0;
	__u64 size;

	if (!addr || addr < 16)
		return req;

	if (bpf_probe_read_user(&hdr, sizeof(hdr), (void *)(addr - 8)))
		return req;

	size = hdr & ~7ULL;
	if (size < 16 || size > (1ULL << 40))
		return req;

	return size - 8;
}

static __always_inline __u32 gfs_stack_id(struct pt_regs *ctx,
					  struct gfs_config *cfg)
{
	if (!cfg || !(cfg->flags & GFS_F_STACKS))
		return 0;
	return bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK);
}

static __always_inline void gfs_put_pending(__u32 op, __u64 size,
					    __u64 old_ptr, struct pt_regs *ctx)
{
	__u32 tid = bpf_get_current_pid_tgid();
	struct gfs_pending p = {};

	p.size = size;
	p.ts = bpf_ktime_get_ns();
	p.caller = PT_REGS_IP(ctx);
	p.old_ptr = old_ptr;
	p.op = op;
	p.tid = tid;
	bpf_map_update_elem(&pending, &tid, &p, BPF_ANY);
}

static __always_inline void gfs_alloc_return(struct pt_regs *ctx, __u32 op)
{
	struct gfs_config *cfg = gfs_cfg();
	__u32 tid = bpf_get_current_pid_tgid();
	struct gfs_pending *p;
	struct gfs_alloc a = {};
	struct gfs_event ev;
	__u64 addr;

	if (!cfg || !(cfg->flags & GFS_F_HEAP))
		return;

	p = bpf_map_lookup_elem(&pending, &tid);
	if (!p)
		return;

	addr = PT_REGS_RC(ctx);
	gfs_init(&ev, addr ? GFS_EV_ALLOC : GFS_EV_ALLOC_FAIL);
	ev.addr = addr;
	ev.size = addr ? gfs_chunk_size(addr, p->size) : 0;
	ev.req_size = p->size;
	ev.caller = p->caller;
	ev.stack_id = gfs_stack_id(ctx, cfg);
	ev.arg1 = p->old_ptr;
	ev.arg2 = op;

	a.addr = addr;
	a.req_size = p->size;
	a.chunk_size = ev.size;
	a.ts = ev.ts;
	a.stack_id = ev.stack_id;
	a.caller = p->caller;
	a.tid = tid;
	a.op = op;
	a.state = 1;

	if (addr) {
		bpf_map_update_elem(&allocs, &addr, &a, BPF_ANY);
		bpf_map_delete_elem(&tombstones, &addr);
	}

	if (op == GFS_OP_REALLOC && p->old_ptr && p->old_ptr != addr) {
		struct gfs_alloc *old = bpf_map_lookup_elem(&allocs, &p->old_ptr);
		if (old)
			old->state = 0;

		struct gfs_tomb t = {};
		t.addr = p->old_ptr;
		t.size = old ? old->chunk_size : 0;
		t.ts = ev.ts;
		t.tid = tid;
		bpf_map_update_elem(&tombstones, &p->old_ptr, &t, BPF_ANY);
	}

	bpf_map_delete_elem(&pending, &tid);
	gfs_emit(&ev);
}

static __always_inline int gfs_free_common(struct pt_regs *ctx, __u32 op)
{
	struct gfs_config *cfg = gfs_cfg();
	__u32 tid = bpf_get_current_pid_tgid();
	__u64 addr = PT_REGS_PARM1(ctx);
	struct gfs_alloc *a;
	struct gfs_event ev;
	struct gfs_tomb t = {};
	__u32 type = GFS_EV_FREE;

	if (!cfg || !addr || !(cfg->flags & GFS_F_HEAP))
		return 0;

	a = bpf_map_lookup_elem(&allocs, &addr);

	if (!a) {
		type = GFS_EV_INVALID_FREE;
	} else if (!a->state) {
		type = GFS_EV_DOUBLE_FREE;
	} else {
		a->state = 0;
	}

	gfs_init(&ev, type);
	ev.addr = addr;
	ev.req_size = a ? a->req_size : 0;
	ev.size = a ? a->chunk_size : gfs_chunk_size(addr, 0);
	ev.stack_id = gfs_stack_id(ctx, cfg);
	ev.arg1 = GFS_OP_FREE;
	ev.arg2 = 0;
	if (!a)
		ev.flags |= GFS_AF_UNKNOWN;

	t.addr = addr;
	t.size = ev.size;
	t.ts = ev.ts;
	t.tid = tid;
	bpf_map_update_elem(&tombstones, &addr, &t, BPF_ANY);

	gfs_emit(&ev);
	return 0;
}

SEC("uprobe/malloc")
int gfs_malloc_enter(struct pt_regs *ctx)
{
	struct gfs_config *cfg = gfs_cfg();
	if (!cfg || !(cfg->flags & GFS_F_HEAP))
		return 0;
	gfs_put_pending(GFS_OP_MALLOC, PT_REGS_PARM1(ctx), 0, ctx);
	return 0;
}

SEC("uretprobe/malloc")
int gfs_malloc_return(struct pt_regs *ctx)
{
	gfs_alloc_return(ctx, GFS_OP_MALLOC);
	return 0;
}

SEC("uprobe/calloc")
int gfs_calloc_enter(struct pt_regs *ctx)
{
	struct gfs_config *cfg = gfs_cfg();
	__u64 nmemb = PT_REGS_PARM1(ctx);
	__u64 size = PT_REGS_PARM2(ctx);
	__u64 total = nmemb * size;

	if (!cfg || !(cfg->flags & GFS_F_HEAP))
		return 0;

	gfs_put_pending(GFS_OP_CALLOC, total, 0, ctx);
	return 0;
}

SEC("uretprobe/calloc")
int gfs_calloc_return(struct pt_regs *ctx)
{
	gfs_alloc_return(ctx, GFS_OP_CALLOC);
	return 0;
}

SEC("uprobe/realloc")
int gfs_realloc_enter(struct pt_regs *ctx)
{
	struct gfs_config *cfg = gfs_cfg();
	if (!cfg || !(cfg->flags & GFS_F_HEAP))
		return 0;
	gfs_put_pending(GFS_OP_REALLOC, PT_REGS_PARM2(ctx), PT_REGS_PARM1(ctx),
			ctx);
	return 0;
}

SEC("uretprobe/realloc")
int gfs_realloc_return(struct pt_regs *ctx)
{
	gfs_alloc_return(ctx, GFS_OP_REALLOC);
	return 0;
}

SEC("uprobe/free")
int gfs_free_enter(struct pt_regs *ctx)
{
	return gfs_free_common(ctx, GFS_OP_FREE);
}

static __always_inline int gfs_read_reg(struct pt_regs *regs, __u64 *out,
					unsigned long offset)
{
	return bpf_probe_read_kernel(out, sizeof(*out), (void *)regs + offset);
}

SEC("raw_tracepoint/sys_enter")
int gfs_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	struct gfs_config *cfg = gfs_cfg();
	struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
	__u64 id = ctx->args[1];
	__u64 di = 0, si = 0, dx = 0, r10 = 0;
	__u32 tid = bpf_get_current_pid_tgid();
	struct gfs_pending_sys ps = {};
	struct gfs_event ev;

	if (!gfs_allowed(cfg) || !regs || !(cfg->flags & GFS_F_SYSCALL))
		return 0;

	gfs_read_reg(regs, &di, offsetof(struct pt_regs, di));
	gfs_read_reg(regs, &si, offsetof(struct pt_regs, si));
	gfs_read_reg(regs, &dx, offsetof(struct pt_regs, dx));
	gfs_read_reg(regs, &r10, offsetof(struct pt_regs, r10));

	ps.id = id;
	ps.ts = bpf_ktime_get_ns();
	ps.tid = tid;
	bpf_map_update_elem(&pending_sys, &tid, &ps, BPF_ANY);

	switch (id) {
	case GFS_NR_MMAP:
		gfs_init(&ev, GFS_EV_MMAP);
		ev.addr = di;
		ev.size = si;
		ev.arg1 = dx;
		ev.arg2 = r10;
		break;
	case GFS_NR_MUNMAP:
		gfs_init(&ev, GFS_EV_MUNMAP);
		ev.addr = di;
		ev.size = si;
		break;
	case GFS_NR_BRK:
		gfs_init(&ev, GFS_EV_BRK);
		ev.addr = di;
		break;
	case GFS_NR_MREMAP:
		gfs_init(&ev, GFS_EV_MREMAP);
		ev.addr = di;
		ev.size = si;
		ev.req_size = dx;
		ev.arg1 = r10;
		break;
	case GFS_NR_READ:
	case GFS_NR_PREAD64:
	case GFS_NR_RECVFROM:
		gfs_init(&ev, GFS_EV_MEM_ACCESS);
		ev.addr = si;
		ev.size = dx;
		ev.arg1 = id;
		ev.arg2 = 1; /* userspace memory is written */
		break;
	case GFS_NR_WRITE:
	case GFS_NR_PWRITE64:
	case GFS_NR_SENDTO:
		gfs_init(&ev, GFS_EV_MEM_ACCESS);
		ev.addr = si;
		ev.size = dx;
		ev.arg1 = id;
		ev.arg2 = 2; /* userspace memory is read */
		break;
	default:
		return 0;
	}

	gfs_emit(&ev);
	return 0;
}

SEC("raw_tracepoint/sys_exit")
int gfs_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
	struct gfs_config *cfg = gfs_cfg();
	__u32 tid = bpf_get_current_pid_tgid();
	struct gfs_pending_sys *ps;
	struct gfs_event ev;
	__u64 ret = ctx->args[1];

	ps = bpf_map_lookup_elem(&pending_sys, &tid);
	if (!ps)
		return 0;

	if (!gfs_allowed(cfg) || !(cfg->flags & GFS_F_SYSCALL)) {
		bpf_map_delete_elem(&pending_sys, &tid);
		return 0;
	}

	if (ps->id == GFS_NR_MMAP || ps->id == GFS_NR_BRK ||
	    ps->id == GFS_NR_MREMAP) {
		gfs_init(&ev, GFS_EV_SYSCALL_RET);
		ev.addr = ret;
		ev.arg1 = ps->id;
		gfs_emit(&ev);
	}

	bpf_map_delete_elem(&pending_sys, &tid);
	return 0;
}
