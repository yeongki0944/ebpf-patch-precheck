package bpfload

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	EvExec = 1
	EvExit = 2
	EvOpen = 3
	EvMmap = 4
)

// kflags (patchscope.h PS_KF_*)
const (
	KFKPathComplete  = 0x1
	KFKPathTruncated = 0x2
	KFNlinkZero      = 0x4
)

// EventSize 는 struct ps_event 크기 (patchscope.h 와 일치해야 함).
const EventSize = 1000

type Event struct {
	TsNs          uint64
	StartBootNs   uint64
	ParentStartNs uint64
	Ino           uint64
	Ret           int64
	Type          uint32
	PID           uint32 // thread id
	TGID          uint32
	PPID          uint32
	UID           uint32
	Dev           uint32 // kernel s_dev
	Flags         uint32
	Prot          uint32
	DFD           int32
	HasIdent      bool
	KFlags        uint32
	Comm          string
	CgroupDfl     string // cgroup v2 leaf 이름
	CgroupPids    string // cgroup v1 pids leaf 이름
	Path          string // 요청 경로
	KPath         string // 커널 dentry 경로 (완전할 때만, 마운트 네임스페이스 루트 기준)
}

// Decode 는 reflection 없이 고정 오프셋으로 디코드한다.
// perf 샘플은 정렬 패딩이 붙을 수 있으므로 EventSize 이상이면 허용.
func Decode(b []byte, e *Event) error {
	if len(b) < EventSize {
		return fmt.Errorf("short event: %d", len(b))
	}
	le := binary.LittleEndian
	e.TsNs = le.Uint64(b[0:])
	e.StartBootNs = le.Uint64(b[8:])
	e.ParentStartNs = le.Uint64(b[16:])
	e.Ino = le.Uint64(b[24:])
	e.Ret = int64(le.Uint64(b[32:]))
	e.Type = le.Uint32(b[40:])
	e.PID = le.Uint32(b[44:])
	e.TGID = le.Uint32(b[48:])
	e.PPID = le.Uint32(b[52:])
	e.UID = le.Uint32(b[56:])
	e.Dev = le.Uint32(b[60:])
	e.Flags = le.Uint32(b[64:])
	e.Prot = le.Uint32(b[68:])
	e.DFD = int32(le.Uint32(b[72:]))
	e.HasIdent = le.Uint32(b[76:]) != 0
	e.KFlags = le.Uint32(b[80:])
	klen := le.Uint32(b[84:])
	e.Comm = cstr(b[88:104])
	e.CgroupDfl = cstr(b[104:168])
	e.CgroupPids = cstr(b[168:232])
	e.Path = cstr(b[232:488])
	e.KPath = ""
	if e.KFlags&KFKPathComplete != 0 && e.KFlags&KFKPathTruncated == 0 && klen <= 512 {
		e.KPath = AssembleKPath(b[488 : 488+klen])
	}
	if e.Type < EvExec || e.Type > EvMmap {
		return fmt.Errorf("unknown event type %d", e.Type)
	}
	return nil
}

// AssembleKPath 는 leaf→root 순서의 NUL 구분 이름을 절대 경로로 만든다.
// 루트 dentry 이름("/")은 건너뛴다.
func AssembleKPath(raw []byte) string {
	parts := bytes.Split(bytes.TrimRight(raw, "\x00"), []byte{0})
	var out []string
	for i := len(parts) - 1; i >= 0; i-- {
		p := string(parts[i])
		if p == "" || p == "/" {
			continue
		}
		out = append(out, p)
	}
	return "/" + strings.Join(out, "/")
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
