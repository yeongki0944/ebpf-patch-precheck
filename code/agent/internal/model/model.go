// Package model 은 에이전트가 서버로 보내는 데이터 형식을 정의한다.
// 서버(API schema v1)와 필드 이름을 맞춘다.
package model

import "time"

const SchemaVersion = "1"

// Record.Kind
const (
	KindProcess    = "process"         // 스냅샷에서 처음 본 프로세스 인스턴스 (현재 exe)
	KindExec       = "exec"            // 실행 이벤트
	KindExit       = "exit"            // 프로세스 종료
	KindOpen       = "file_open"       // 파일 열기 시도 (성공/실패)
	KindMmap       = "file_mmap"       // 파일 기반 mmap 시도
	KindMapped     = "mapped_file"     // /proc/PID/maps 의 파일 기반 매핑 (현재 상태)
	KindOpenFD     = "open_fd"         // /proc/PID/fd 의 열린 파일 (현재 상태)
	KindSnapMissed = "snapshot_missed" // 단기 프로세스 등으로 /proc 상태를 읽지 못함
	KindInventory  = "inventory_changed"
)

// Record.Source
const (
	SourceEBPF     = "ebpf"
	SourceSnapshot = "proc_snapshot"
	SourceFollowup = "proc_exec_followup"
	SourceAgent    = "agent"
)

// FileRef.PathStatus
const (
	PathVerified   = "verified"       // 요청 경로를 stat 한 dev/ino 가 이벤트 식별자와 일치
	PathInodeIndex = "inode_index"    // 같은 세션에서 검증된 (dev,ino)->경로 색인으로 확인
	PathKernel     = "kernel"         // /proc maps·exe·fd 에서 커널이 보고한 경로
	PathUnresolved = "unresolved"     // dev/ino 는 있으나 경로 확정 실패. RPM 매핑에 사용 안 함
	PathRequested  = "requested_only" // 실패한 열기 등 식별자 없음. RPM 매핑에 사용 안 함
)

// FileRef.Ownership
const (
	OwnRPM       = "rpm"
	OwnUnmanaged = "unmanaged" // 경로 확정, RPM 소유 아님. 영향 없음으로 처리하지 않음
	OwnUnknown   = "unknown"   // 경로 미확정이라 판정 불가
	OwnDeleted   = "deleted"   // 삭제된 파일. 현재 경로의 새 파일로 해석하지 않음
)

type HostInfo struct {
	HostID   string `json:"host_id"` // /etc/machine-id
	BootID   string `json:"boot_id"`
	Hostname string `json:"hostname"`
	Kernel   string `json:"kernel"`
	OSID     string `json:"os_id"`
	OSVer    string `json:"os_version"`
}

type ProcRef struct {
	PID        uint32 `json:"pid"`         // tgid
	StartTicks uint64 `json:"start_ticks"` // /proc/PID/stat starttime (clock ticks since boot)
	Key        string `json:"key"`         // host_id:boot_id:pid:start_ticks
}

type FileRef struct {
	Path          string   `json:"path,omitempty"`
	RequestedPath string   `json:"requested_path,omitempty"`
	PathStatus    string   `json:"path_status"`
	Dev           string   `json:"dev,omitempty"` // "major:minor"
	Ino           uint64   `json:"ino,omitempty"`
	Deleted       bool     `json:"deleted,omitempty"`
	Ownership     string   `json:"ownership"`
	Packages      []string `json:"packages,omitempty"` // N-E:V-R.A
}

type Record struct {
	Kind       string     `json:"kind"`
	Source     string     `json:"source"`
	TsMonoNs   uint64     `json:"ts_mono_ns,omitempty"`
	TsUTC      time.Time  `json:"ts_utc"`
	LastTsUTC  *time.Time `json:"last_ts_utc,omitempty"`
	Count      uint64     `json:"count,omitempty"` // 집계된 동일 이벤트 수
	Proc       ProcRef    `json:"proc"`
	TID        uint32     `json:"tid,omitempty"`
	PPID       uint32     `json:"ppid,omitempty"`
	ParentKey  string     `json:"parent_key,omitempty"`
	Comm       string     `json:"comm,omitempty"`
	UID        *uint32    `json:"uid,omitempty"`
	Unit       string     `json:"unit,omitempty"`
	UnitSource string     `json:"unit_source,omitempty"` // cgroup | parent | none
	File       *FileRef   `json:"file,omitempty"`
	OK         *bool      `json:"ok,omitempty"`
	Errno      int        `json:"errno,omitempty"`
	Flags      uint32     `json:"flags,omitempty"`
	Prot       uint32     `json:"prot,omitempty"`
	Perms      string     `json:"perms,omitempty"`
	ExitCode   *int       `json:"exit_code,omitempty"`
	Signal     *int       `json:"signal,omitempty"`
	Note       string     `json:"note,omitempty"`
}

// Counters 는 수집 손실·품질 지표. 손실 항목이 0 이 아니면 해당 구간은 불완전.
type Counters struct {
	EventsReceived   uint64 `json:"events_received"`
	KernelOutputFail uint64 `json:"kernel_output_fail"` // 손실: perf 출력 실패
	PerfLost         uint64 `json:"perf_lost"`          // 손실: perf buffer overwrite
	InflightFull     uint64 `json:"inflight_full"`      // 손실: enter/exit 연결 map 포화
	QueueDrop        uint64 `json:"queue_drop"`         // 손실: 사용자 공간 큐 포화
	FollowupDrop     uint64 `json:"followup_drop"`      // 손실: exec 후속 maps 조회 큐 포화
	SpoolDropBatches uint64 `json:"spool_drop_batches"` // 손실: spool 한도 초과로 삭제
	SpoolDropRecords uint64 `json:"spool_drop_records"`
	IdentFail        uint64 `json:"ident_fail"` // 품질: fd->inode 식별 실패
	PathFail         uint64 `json:"path_fail"`  // 품질: 경로 문자열 읽기 실패
	DecodeFail       uint64 `json:"decode_fail"`
	SnapshotMissed   uint64 `json:"snapshot_missed"`
	Aggregated       uint64 `json:"aggregated"` // 집계로 원시 레코드를 생략한 수 (count 에 반영)
	Filtered         uint64 `json:"filtered"`   // 필터 정책으로 제외
}

func (c *Counters) Add(o Counters) {
	c.EventsReceived += o.EventsReceived
	c.KernelOutputFail += o.KernelOutputFail
	c.PerfLost += o.PerfLost
	c.InflightFull += o.InflightFull
	c.QueueDrop += o.QueueDrop
	c.FollowupDrop += o.FollowupDrop
	c.SpoolDropBatches += o.SpoolDropBatches
	c.SpoolDropRecords += o.SpoolDropRecords
	c.IdentFail += o.IdentFail
	c.PathFail += o.PathFail
	c.DecodeFail += o.DecodeFail
	c.SnapshotMissed += o.SnapshotMissed
	c.Aggregated += o.Aggregated
	c.Filtered += o.Filtered
}

// LossFree 는 이벤트 손실이 없었는지 여부.
func (c Counters) LossFree() bool {
	return c.KernelOutputFail == 0 && c.PerfLost == 0 && c.InflightFull == 0 &&
		c.QueueDrop == 0 && c.FollowupDrop == 0 && c.SpoolDropBatches == 0 && c.DecodeFail == 0
}

// FilterPolicy 는 결과 해석을 위해 배치에 함께 싣는 수집 정책.
type FilterPolicy struct {
	ExcludePathPrefixes []string `json:"exclude_path_prefixes"`
	ExcludeComms        []string `json:"exclude_comms"`
	Aggregation         string   `json:"aggregation"`
}

type Batch struct {
	SchemaVersion   string       `json:"schema_version"`
	AgentID         string       `json:"agent_id"`
	AgentVersion    string       `json:"agent_version"`
	BatchID         string       `json:"batch_id"`
	SessionID       string       `json:"session_id"`
	Seq             uint64       `json:"seq"`
	Host            HostInfo     `json:"host"`
	InventoryID     string       `json:"inventory_id"`
	CreatedAt       time.Time    `json:"created_at"`
	WindowStart     time.Time    `json:"window_start"`
	Reason          string       `json:"reason"`
	Complete        bool         `json:"complete"`
	Delta           Counters     `json:"delta"`
	Total           Counters     `json:"total"`
	DroppedBatchIDs []string     `json:"dropped_batch_ids,omitempty"`
	Policy          FilterPolicy `json:"policy"`
	Records         []Record     `json:"records"`
}
