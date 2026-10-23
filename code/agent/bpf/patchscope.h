/* 커널/사용자 공간 공유 이벤트 레이아웃. Go 쪽 Decode 와 오프셋을 맞춘다 (352 bytes). */
#ifndef PATCHSCOPE_H
#define PATCHSCOPE_H

#define PS_PATH_LEN 256
#define PS_COMM_LEN 16

enum ps_event_type {
	PS_EV_EXEC = 1,
	PS_EV_EXIT = 2,
	PS_EV_OPEN = 3,
	PS_EV_MMAP = 4,
};

/* 커널 쪽 손실/실패 카운터 (per-CPU) */
enum ps_stat {
	PS_STAT_OUTPUT_FAIL   = 0, /* perf buffer 출력 실패 = 커널 이벤트 손실 */
	PS_STAT_INFLIGHT_FULL = 1, /* enter/exit 연결 map 가득 참 */
	PS_STAT_IDENT_FAIL    = 2, /* fd -> inode 식별 실패 */
	PS_STAT_PATH_FAIL     = 3, /* 경로 문자열 읽기 실패 */
	PS_STAT_MAX           = 4,
};

struct ps_event {
	__u64 ts_ns;             /* bpf_ktime_get_ns (CLOCK_MONOTONIC) */
	__u64 start_boottime_ns; /* thread group leader 시작 시각 (boottime ns) */
	__u64 parent_start_ns;   /* real_parent 의 leader 시작 시각 */
	__u64 ino;
	__s64 ret;               /* open: fd/-errno, mmap: addr/-errno, exit: exit_code */
	__u32 type;
	__u32 pid;               /* thread id */
	__u32 tgid;              /* process id */
	__u32 ppid;
	__u32 uid;
	__u32 dev;               /* kernel s_dev (MAJOR<<20 | MINOR) */
	__u32 flags;             /* open flags / mmap flags */
	__u32 prot;              /* mmap prot */
	__s32 dfd;
	__u32 has_ident;         /* dev/ino 유효 여부 */
	char comm[PS_COMM_LEN];
	char path[PS_PATH_LEN];  /* 요청 경로 (상대 경로 가능, mmap 은 비어 있음) */
};

#endif
