/* 커널/사용자 공간 공유 이벤트 레이아웃. Go 쪽 Decode 와 오프셋을 맞춘다 (1000 bytes). */
#ifndef PATCHSCOPE_H
#define PATCHSCOPE_H

#define PS_PATH_LEN  256
#define PS_KPATH_LEN 512   /* leaf→root 순서, NUL 구분 이름 목록 */
#define PS_COMM_LEN  16
#define PS_CG_LEN    64

enum ps_event_type {
	PS_EV_EXEC = 1,
	PS_EV_EXIT = 2,
	PS_EV_OPEN = 3,
	PS_EV_MMAP = 4,
};

/* kflags */
#define PS_KF_KPATH_COMPLETE  0x1 /* 파일시스템 루트까지 도달 */
#define PS_KF_KPATH_TRUNCATED 0x2 /* 깊이/길이 한도 초과 */
#define PS_KF_NLINK_ZERO      0x4 /* 이벤트 시점에 이미 링크가 0 (삭제됨) */

/* 커널 쪽 손실/실패 카운터 (per-CPU) */
enum ps_stat {
	PS_STAT_OUTPUT_FAIL   = 0, /* perf buffer 출력 실패 = 커널 이벤트 손실 */
	PS_STAT_INFLIGHT_FULL = 1, /* enter/exit 연결 map 가득 참 */
	PS_STAT_IDENT_FAIL    = 2, /* fd -> inode 식별 실패 */
	PS_STAT_PATH_FAIL     = 3, /* 경로 문자열 읽기 실패 */
	PS_STAT_MAX           = 4,
};

struct ps_event {
	__u64 ts_ns;             /*   0 bpf_ktime_get_ns (CLOCK_MONOTONIC) */
	__u64 start_boottime_ns; /*   8 thread group leader 시작 시각 (boottime ns) */
	__u64 parent_start_ns;   /*  16 real_parent 의 leader 시작 시각 */
	__u64 ino;               /*  24 */
	__s64 ret;               /*  32 open: fd/-errno, mmap: addr/-errno, exit: exit_code */
	__u32 type;              /*  40 */
	__u32 pid;               /*  44 thread id */
	__u32 tgid;              /*  48 process id */
	__u32 ppid;              /*  52 */
	__u32 uid;               /*  56 */
	__u32 dev;               /*  60 kernel s_dev (MAJOR<<20 | MINOR) */
	__u32 flags;             /*  64 open flags / mmap flags */
	__u32 prot;              /*  68 mmap prot */
	__s32 dfd;               /*  72 */
	__u32 has_ident;         /*  76 dev/ino 유효 여부 */
	__u32 kflags;            /*  80 PS_KF_* */
	__u32 kpath_len;         /*  84 kpath 사용 바이트 */
	char comm[PS_COMM_LEN];  /*  88 */
	char cg_dfl[PS_CG_LEN];  /* 104 cgroup v2(default hierarchy) leaf 이름 */
	char cg_pids[PS_CG_LEN]; /* 168 cgroup v1 pids 계층 leaf 이름 (RHEL 8) */
	char path[PS_PATH_LEN];  /* 232 요청 경로 (상대 경로 가능) */
	char kpath[PS_KPATH_LEN];/* 488 커널 dentry 경로 이름 (leaf 부터) */
};                           /* 1000 */

#endif
