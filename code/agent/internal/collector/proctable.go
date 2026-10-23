package collector

import (
	"fmt"

	"github.com/yeongki0944/ebpf-patch-precheck/code/agent/internal/procfs"
)

// procInfo 는 프로세스 인스턴스(host_id+boot_id+pid+start_time) 단위 상태.
type procInfo struct {
	key        string
	pid        uint32
	startTicks uint64
	unit       string
	unitSource string
	otherNS    bool // 다른 mount namespace: RPM 소유 해석 미지원
	exited     bool
	// /proc/PID/maps 에서 배운 (dev,ino)->경로. mmap 이벤트 경로 확정에 사용
	mapsIdx    map[procfs.DevIno]string
	mapsLoaded bool
}

type procTable struct {
	hostID, bootID string
	selfNS         string
	byPID          map[uint32]*procInfo
}

func newProcTable(hostID, bootID string) *procTable {
	return &procTable{hostID: hostID, bootID: bootID, selfNS: procfs.MountNS(uint32(selfPID())), byPID: map[uint32]*procInfo{}}
}

func (t *procTable) keyOf(pid uint32, startTicks uint64) string {
	return fmt.Sprintf("%s:%s:%d:%d", t.hostID, t.bootID, pid, startTicks)
}

// get 은 (pid,start) 가 같은 인스턴스를 돌려주고, PID 가 재사용됐으면 새 인스턴스로 교체한다.
func (t *procTable) get(pid uint32, startTicks uint64) (*procInfo, bool) {
	if p, ok := t.byPID[pid]; ok && p.startTicks == startTicks {
		return p, false
	}
	p := &procInfo{key: t.keyOf(pid, startTicks), pid: pid, startTicks: startTicks}
	t.byPID[pid] = p
	return p, true
}

// fillUnit 은 cgroup 으로 systemd unit 을 찾고, 실패하면 부모 unit 을 보조 근거로 사용한다.
func (t *procTable) fillUnit(p *procInfo, ppid uint32, parentTicks uint64) {
	if unit, ok := procfs.UnitFromCgroup(p.pid); ok {
		p.unit, p.unitSource = unit, "cgroup"
		if unit == "" {
			p.unitSource = "none"
		}
	} else if pp, ok := t.byPID[ppid]; ok && pp.startTicks == parentTicks && pp.unit != "" {
		p.unit, p.unitSource = pp.unit, "parent"
	} else {
		p.unitSource = "none"
	}
	if ns := procfs.MountNS(p.pid); ns != "" && t.selfNS != "" && ns != t.selfNS {
		p.otherNS = true
	}
}

// sweep 은 종료된 인스턴스를 정리한다 (배치 전송 후 호출).
func (t *procTable) sweep() {
	for pid, p := range t.byPID {
		if p.exited {
			delete(t.byPID, pid)
		}
	}
}

// lookupMapped 는 프로세스의 현재 maps 에서 (dev,ino) 의 커널 경로를 찾는다 (프로세스별 1회 읽기, 실패 시 재시도).
func (t *procTable) lookupMapped(p *procInfo, id procfs.DevIno) (string, bool, bool) {
	if p.mapsIdx == nil || !p.mapsLoaded {
		maps, err := procfs.ReadMaps(p.pid)
		if err != nil {
			return "", false, false
		}
		if st, err := procfs.ReadStat(p.pid); err != nil || st.StartTicks != p.startTicks {
			return "", false, false // PID 재사용: 다른 프로세스의 maps 를 쓰지 않음
		}
		p.mapsIdx = map[procfs.DevIno]string{}
		for _, m := range maps {
			path := m.Path
			if m.Deleted {
				path += deletedMark
			}
			p.mapsIdx[m.ID] = path
		}
		p.mapsLoaded = true
	}
	path, ok := p.mapsIdx[id]
	if !ok {
		p.mapsLoaded = false // 이후 매핑이 추가됐을 수 있으므로 다음에 다시 읽음
		return "", false, false
	}
	if len(path) > len(deletedMark) && path[len(path)-len(deletedMark):] == deletedMark {
		return path[:len(path)-len(deletedMark)], true, true
	}
	return path, false, true
}

const deletedMark = "\x00deleted"
