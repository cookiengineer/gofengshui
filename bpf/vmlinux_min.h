#ifndef GFS_VMLINUX_MIN_H
#define GFS_VMLINUX_MIN_H

/*
 * Minimal x86_64 kernel pt_regs layout. Only the stable syscall ABI fields
 * are used. This intentionally avoids a generated vmlinux.h so the BPF
 * object stays small and builds without kernel BTF.
 */
struct pt_regs {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long bp;
	unsigned long bx;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long ax;
	unsigned long cx;
	unsigned long dx;
	unsigned long si;
	unsigned long di;
	unsigned long orig_ax;
	unsigned long ip;
	unsigned long cs;
	unsigned long flags;
	unsigned long sp;
	unsigned long ss;
};

#endif
