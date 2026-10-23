// SPDX-License-Identifier: GPL-2.0
/*
 * PatchScope 수집 프로그램 (CO-RE, tracepoint 기반)
 *  - sched_process_exec / sched_process_exit : 실행·종료 이력
 *  - sys_{enter,exit}_openat (+ open)        : 성공/실패한 파일 열기, 성공 시 dev/inode
 *  - sys_{enter,exit}_mmap                   : 파일 기반 매핑의 dev/inode, prot
 * 전달은 RHEL 8 호환을 위해 perf event array 를 사용한다.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "patchscope.h"

char LICENSE[] SEC("license") = "GPL";

#define PS_AT_FDCWD       -100
#define PS_MAP_ANONYMOUS  0x20
#define PS_MAX_ERRNO      4095

/* 사용자 공간에서 로드 전에 설정: 에이전트 자신의 이벤트 제외 */
volatile const __u32 agent_tgid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ps_event);
} scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, PS_STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

struct open_args {
	__u64 filename;
	__s32 dfd;
	__u32 flags;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct open_args);
} open_inflight SEC(".maps");

struct mmap_args {
	__s32 fd;
	__u32 prot;
	__u32 flags;
	__u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct mmap_args);
} mmap_inflight SEC(".maps");

/* 5.5 이전 커널(RHEL 8 4.18 포함)의 필드명 */
struct task_struct___pre55 {
	__u64 real_start_time;
} __attribute__((preserve_access_index));

static __always_inline void stat_inc(__u32 key)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &key);
	if (v)
		(*v)++;
}

/* 에이전트 자신과 에이전트가 직접 실행한 자식(rpm 조회 등)의 이벤트는 제외 */
static __always_inline int is_agent(void)
{
	struct task_struct *task;

	if (!agent_tgid)
		return 0;
	if ((bpf_get_current_pid_tgid() >> 32) == agent_tgid)
		return 1;
	task = (struct task_struct *)bpf_get_current_task();
	return BPF_CORE_READ(task, real_parent, tgid) == agent_tgid;
}

/* /proc/PID/stat starttime 과 같은 기준(boottime)의 프로세스 시작 시각 */
static __always_inline __u64 proc_start_ns(struct task_struct *task)
{
	struct task_struct *leader = BPF_CORE_READ(task, group_leader);

	if (bpf_core_field_exists(leader->start_boottime))
		return BPF_CORE_READ(leader, start_boottime);

	struct task_struct___pre55 *old = (void *)leader;
	return BPF_CORE_READ(old, real_start_time);
}

static __always_inline void file_ident(struct file *f, struct ps_event *e)
{
	struct inode *in = BPF_CORE_READ(f, f_inode);

	if (!in) {
		stat_inc(PS_STAT_IDENT_FAIL);
		return;
	}
	e->ino = BPF_CORE_READ(in, i_ino);
	e->dev = BPF_CORE_READ(in, i_sb, s_dev);
	e->has_ident = 1;
}

static __always_inline void fd_ident(struct task_struct *task, long fd, struct ps_event *e)
{
	struct file **fds = BPF_CORE_READ(task, files, fdt, fd);
	unsigned int max_fds = BPF_CORE_READ(task, files, fdt, max_fds);
	struct file *f = NULL;

	if (fd < 0 || (unsigned long)fd >= max_fds) {
		stat_inc(PS_STAT_IDENT_FAIL);
		return;
	}
	if (bpf_probe_read_kernel(&f, sizeof(f), &fds[fd]) || !f) {
		stat_inc(PS_STAT_IDENT_FAIL);
		return;
	}
	file_ident(f, e);
}

static __always_inline struct ps_event *new_event(__u32 type, struct task_struct **task_out)
{
	__u32 zero = 0;
	struct ps_event *e = bpf_map_lookup_elem(&scratch, &zero);
	struct task_struct *task;
	__u64 id;

	if (!e)
		return NULL;

	task = (struct task_struct *)bpf_get_current_task();
	id = bpf_get_current_pid_tgid();

	e->ts_ns = bpf_ktime_get_ns();
	e->start_boottime_ns = proc_start_ns(task);
	e->parent_start_ns = proc_start_ns(BPF_CORE_READ(task, real_parent));
	e->ino = 0;
	e->ret = 0;
	e->type = type;
	e->pid = (__u32)id;
	e->tgid = id >> 32;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->dev = 0;
	e->flags = 0;
	e->prot = 0;
	e->dfd = 0;
	e->has_ident = 0;
	e->path[0] = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	*task_out = task;
	return e;
}

static __always_inline void emit(void *ctx, struct ps_event *e)
{
	if (bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e)))
		stat_inc(PS_STAT_OUTPUT_FAIL);
}

/* ---------------------------------------------------------------- exec/exit */

SEC("tracepoint/sched/sched_process_exec")
int tp_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct task_struct *task;
	struct ps_event *e;
	struct file *exe;
	unsigned int off;

	if (is_agent())
		return 0;
	e = new_event(PS_EV_EXEC, &task);
	if (!e)
		return 0;

	off = ctx->__data_loc_filename & 0xFFFF;
	if (bpf_probe_read_kernel_str(e->path, sizeof(e->path), (void *)ctx + off) < 0)
		stat_inc(PS_STAT_PATH_FAIL);

	exe = BPF_CORE_READ(task, mm, exe_file);
	if (exe)
		file_ident(exe, e);
	else
		stat_inc(PS_STAT_IDENT_FAIL);

	emit(ctx, e);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int tp_exit(void *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct task_struct *task;
	struct ps_event *e;

	/* 프로세스(thread group leader) 종료만 기록 */
	if ((__u32)id != (__u32)(id >> 32) || is_agent())
		return 0;
	e = new_event(PS_EV_EXIT, &task);
	if (!e)
		return 0;
	e->ret = BPF_CORE_READ(task, exit_code);
	emit(ctx, e);
	return 0;
}

/* ---------------------------------------------------------------- open */

static __always_inline int open_enter(__s32 dfd, __u64 filename, __u32 flags)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct open_args a = {
		.filename = filename,
		.dfd = dfd,
		.flags = flags,
	};

	if (is_agent())
		return 0;
	if (bpf_map_update_elem(&open_inflight, &id, &a, BPF_ANY))
		stat_inc(PS_STAT_INFLIGHT_FULL);
	return 0;
}

static __always_inline int open_exit(void *ctx, long ret)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct open_args *ap = bpf_map_lookup_elem(&open_inflight, &id);
	struct task_struct *task;
	struct open_args a;
	struct ps_event *e;

	if (!ap)
		return 0;
	a = *ap;
	bpf_map_delete_elem(&open_inflight, &id);

	e = new_event(PS_EV_OPEN, &task);
	if (!e)
		return 0;
	e->ret = ret;
	e->flags = a.flags;
	e->dfd = a.dfd;
	if (bpf_probe_read_user_str(e->path, sizeof(e->path), (void *)a.filename) < 0)
		stat_inc(PS_STAT_PATH_FAIL);
	if (ret >= 0)
		fd_ident(task, ret, e);

	emit(ctx, e);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
	return open_enter((__s32)ctx->args[0], ctx->args[1], (__u32)ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tp_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
	return open_exit(ctx, ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_open")
int tp_enter_open(struct trace_event_raw_sys_enter *ctx)
{
	return open_enter(PS_AT_FDCWD, ctx->args[0], (__u32)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_exit_open")
int tp_exit_open(struct trace_event_raw_sys_exit *ctx)
{
	return open_exit(ctx, ctx->ret);
}

/* ---------------------------------------------------------------- mmap */

SEC("tracepoint/syscalls/sys_enter_mmap")
int tp_enter_mmap(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct mmap_args a = {
		.fd = (__s32)ctx->args[4],
		.prot = (__u32)ctx->args[2],
		.flags = (__u32)ctx->args[3],
	};

	if (a.fd < 0 || (a.flags & PS_MAP_ANONYMOUS) || is_agent())
		return 0;
	if (bpf_map_update_elem(&mmap_inflight, &id, &a, BPF_ANY))
		stat_inc(PS_STAT_INFLIGHT_FULL);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_mmap")
int tp_exit_mmap(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct mmap_args *ap = bpf_map_lookup_elem(&mmap_inflight, &id);
	struct task_struct *task;
	struct mmap_args a;
	struct ps_event *e;
	long ret;

	if (!ap)
		return 0;
	a = *ap;
	bpf_map_delete_elem(&mmap_inflight, &id);

	e = new_event(PS_EV_MMAP, &task);
	if (!e)
		return 0;
	ret = ctx->ret;
	e->ret = ret;
	e->flags = a.flags;
	e->prot = a.prot;
	e->dfd = a.fd;
	/* 실패(-errno)여도 기록. 성공 시에만 fd 의 inode 식별 */
	if (!(ret < 0 && ret >= -PS_MAX_ERRNO))
		fd_ident(task, a.fd, e);

	emit(ctx, e);
	return 0;
}
