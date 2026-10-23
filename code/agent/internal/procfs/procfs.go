// Package procfs 는 /proc 에서 프로세스 현재 상태(exe, maps, fd, cgroup)를 읽는다.
package procfs

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const deletedSuffix = " (deleted)"

type DevIno struct {
	Dev string // "major:minor" (decimal)
	Ino uint64
}

func (d DevIno) Valid() bool { return d.Dev != "" && d.Ino != 0 }

// DevFromKernel 은 커널 내부 s_dev(MAJOR<<20|MINOR)를 "major:minor" 로 바꾼다.
func DevFromKernel(sdev uint32) string {
	return fmt.Sprintf("%d:%d", sdev>>20, sdev&0xfffff)
}

// DevFromStat 은 stat(2) 의 st_dev 를 "major:minor" 로 바꾼다.
func DevFromStat(dev uint64) string {
	return fmt.Sprintf("%d:%d", unix.Major(dev), unix.Minor(dev))
}

// StatDevIno 는 경로를 따라가 stat 한 식별자를 돌려준다.
func StatDevIno(path string) (DevIno, bool) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return DevIno{}, false
	}
	return DevIno{Dev: DevFromStat(st.Dev), Ino: st.Ino}, true
}

type Stat struct {
	PID        uint32
	Comm       string
	State      string
	PPID       uint32
	StartTicks uint64
}

// ReadStat 은 /proc/PID/stat 을 파싱한다 (comm 에 공백·괄호가 있어도 안전하게).
func ReadStat(pid uint32) (Stat, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return Stat{}, err
	}
	s := string(b)
	l, r := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if l < 0 || r < l {
		return Stat{}, fmt.Errorf("malformed stat")
	}
	f := strings.Fields(s[r+1:])
	// f[0]=state(3) f[1]=ppid(4) ... f[19]=starttime(22)
	if len(f) < 20 {
		return Stat{}, fmt.Errorf("short stat")
	}
	ppid, _ := strconv.ParseUint(f[1], 10, 32)
	start, err := strconv.ParseUint(f[19], 10, 64)
	if err != nil {
		return Stat{}, err
	}
	return Stat{PID: pid, Comm: s[l+1 : r], State: f[0], PPID: uint32(ppid), StartTicks: start}, nil
}

func ReadUID(pid uint32) (uint32, bool) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "Uid:") {
			ff := strings.Fields(sc.Text())
			if len(ff) >= 2 {
				v, err := strconv.ParseUint(ff[1], 10, 32)
				return uint32(v), err == nil
			}
		}
	}
	return 0, false
}

// Link 은 /proc 심볼릭 링크(exe, cwd, fd/N)를 읽고 " (deleted)" 여부를 분리한다.
func Link(p string) (target string, deleted bool, err error) {
	t, err := os.Readlink(p)
	if err != nil {
		return "", false, err
	}
	if strings.HasSuffix(t, deletedSuffix) {
		return strings.TrimSuffix(t, deletedSuffix), true, nil
	}
	return t, false, nil
}

type Exe struct {
	Path    string
	Deleted bool
	ID      DevIno
	OK      bool
}

func ReadExe(pid uint32) Exe {
	p := fmt.Sprintf("/proc/%d/exe", pid)
	t, del, err := Link(p)
	if err != nil {
		return Exe{}
	}
	id, ok := StatDevIno(p) // 삭제되어도 /proc 링크로 원래 inode 를 stat 가능
	return Exe{Path: t, Deleted: del, ID: id, OK: ok}
}

type Mapping struct {
	Path    string
	Deleted bool
	ID      DevIno
	Perms   string // 같은 파일의 여러 구간 권한을 합친 값 (예: "r-xp,r--p")
}

// ReadMaps 는 파일 기반 매핑을 파일 단위로 합쳐 돌려준다.
func ReadMaps(pid uint32) ([]Mapping, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	idx := map[DevIno]int{}
	var out []Mapping
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		// addr perms offset dev inode path
		ff := strings.SplitN(sc.Text(), " ", 6)
		if len(ff) < 6 {
			continue
		}
		ino, _ := strconv.ParseUint(ff[4], 10, 64)
		path := strings.TrimLeft(ff[5], " ")
		if ino == 0 || !strings.HasPrefix(path, "/") {
			continue
		}
		del := false
		if strings.HasSuffix(path, deletedSuffix) {
			path, del = strings.TrimSuffix(path, deletedSuffix), true
		}
		id := DevIno{Dev: hexDev(ff[3]), Ino: ino}
		if i, ok := idx[id]; ok {
			if !strings.Contains(out[i].Perms, ff[1]) {
				out[i].Perms += "," + ff[1]
			}
			continue
		}
		idx[id] = len(out)
		out = append(out, Mapping{Path: path, Deleted: del, ID: id, Perms: ff[1]})
	}
	return out, sc.Err()
}

func hexDev(s string) string {
	maj, min, ok := strings.Cut(s, ":")
	if !ok {
		return s
	}
	a, _ := strconv.ParseUint(maj, 16, 32)
	b, _ := strconv.ParseUint(min, 16, 32)
	return fmt.Sprintf("%d:%d", a, b)
}

type OpenFile struct {
	FD      int
	Path    string
	Deleted bool
	ID      DevIno
}

// ReadFDs 는 열린 fd 중 절대 경로를 가진 파일만 돌려준다 (socket/pipe/anon 제외).
func ReadFDs(pid uint32) ([]OpenFile, error) {
	dir := fmt.Sprintf("/proc/%d/fd", pid)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []OpenFile
	for _, e := range ents {
		fd, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		p := filepath.Join(dir, e.Name())
		t, del, err := Link(p)
		if err != nil || !strings.HasPrefix(t, "/") {
			continue
		}
		id, _ := StatDevIno(p)
		out = append(out, OpenFile{FD: fd, Path: t, Deleted: del, ID: id})
	}
	return out, nil
}

// UnitFromCgroup 은 systemd unit(.service/.scope 등)을 cgroup 경로에서 찾는다.
// cgroup v2("0::/...") 와 v1("N:name=systemd:/...") 모두 처리.
func UnitFromCgroup(pid uint32) (string, bool) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", false
	}
	var path string
	for _, line := range strings.Split(string(b), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[1] == "name=systemd" || (parts[0] == "0" && parts[1] == "") {
			path = parts[2]
			if parts[1] == "name=systemd" {
				break
			}
		}
	}
	comps := strings.Split(path, "/")
	for i := len(comps) - 1; i >= 0; i-- {
		c := comps[i]
		for _, suf := range []string{".service", ".scope", ".socket", ".mount", ".timer"} {
			if strings.HasSuffix(c, suf) {
				return c, true
			}
		}
	}
	return "", true
}

// MountNS 는 /proc/PID/ns/mnt 링크 값 (예: "mnt:[4026531840]").
func MountNS(pid uint32) string {
	t, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", pid))
	if err != nil {
		return ""
	}
	return t
}

// ListPIDs 는 /proc 의 프로세스(tgid) 목록.
func ListPIDs() ([]uint32, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var out []uint32
	for _, e := range ents {
		if v, err := strconv.ParseUint(e.Name(), 10, 32); err == nil {
			out = append(out, uint32(v))
		}
	}
	return out, nil
}

// ClockTicks 는 USER_HZ. x86_64 Linux 는 100 (sysconf 호출 없이 고정, 사전 점검에서 검증).
const ClockTicks = 100

func NsToTicks(ns uint64) uint64 { return ns / (1_000_000_000 / ClockTicks) }

// ResolveRequested 는 openat 의 요청 경로를 프로세스 기준 절대 경로로 만든다.
func ResolveRequested(pid uint32, dfd int32, req string) (string, bool) {
	if req == "" {
		return "", false
	}
	if strings.HasPrefix(req, "/") {
		return filepath.Clean(req), true
	}
	var base string
	var err error
	if dfd == -100 { // AT_FDCWD
		base, _, err = Link(fmt.Sprintf("/proc/%d/cwd", pid))
	} else {
		base, _, err = Link(fmt.Sprintf("/proc/%d/fd/%d", pid, dfd))
	}
	if err != nil || !strings.HasPrefix(base, "/") {
		return "", false
	}
	return filepath.Join(base, req), true
}
