// Package rpminv 는 RPM 인벤토리(패키지 목록, 파일 소유, Requires/Provides)를 읽는다.
// 매 이벤트마다 rpm 을 호출하지 않고, 인벤토리 버전 단위로 한 번 읽어 캐시한다.
package rpminv

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yeongki0944/ebpf-patch-precheck/code/agent/internal/procfs"
)

const (
	nevraFmt       = `%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}`
	nevraRepeatFmt = `%{=NAME}-%{=EPOCHNUM}:%{=VERSION}-%{=RELEASE}.%{=ARCH}`
)

type Package struct {
	NEVRA    string   `json:"nevra"`
	Name     string   `json:"name"`
	Epoch    string   `json:"epoch"`
	Version  string   `json:"version"`
	Release  string   `json:"release"`
	Arch     string   `json:"arch"`
	Requires    []string `json:"requires,omitempty"`
	Provides    []string `json:"provides,omitempty"`
	InstallTime int64    `json:"install_time,omitempty"` // RPM DB 설치 시각 (unix)
}

// Inventory 는 특정 시점의 RPM DB 스냅샷.
type Inventory struct {
	ID         string    `json:"inventory_id"`
	CapturedAt time.Time `json:"captured_at"`
	Packages   []Package `json:"packages"`

	byPath  map[string][]string        // RPM 경로 및 디렉터리 정규화 경로 -> NEVRA
	byInode map[procfs.DevIno][]string // 로드 시점 inode -> NEVRA
	pathOf  map[procfs.DevIno]string
}

// CurrentID 는 설치 패키지 NEVRA 목록의 해시. 인벤토리 변경 감지용 (가벼운 조회).
func CurrentID() (string, []string, error) {
	out, err := exec.Command("rpm", "-qa", "--qf", nevraFmt+`\n`).Output()
	if err != nil {
		return "", nil, fmt.Errorf("rpm -qa: %w", err)
	}
	lines := strings.Fields(string(out))
	sort.Strings(lines)
	h := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(h[:8]), lines, nil
}

// Load 는 전체 인벤토리를 읽는다. 수 초 걸릴 수 있다.
func Load() (*Inventory, error) {
	id, _, err := CurrentID()
	if err != nil {
		return nil, err
	}
	inv := &Inventory{
		ID:         id,
		CapturedAt: time.Now().UTC(),
		byPath:     map[string][]string{},
		byInode:    map[procfs.DevIno][]string{},
		pathOf:     map[procfs.DevIno]string{},
	}
	if err := inv.loadPackages(); err != nil {
		return nil, err
	}
	if err := inv.loadFiles(); err != nil {
		return nil, err
	}
	return inv, nil
}

func (inv *Inventory) loadPackages() error {
	// 패키지 헤더 줄 뒤에 R/P 줄이 이어진다
	q := "@\t" + nevraFmt + "\t%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{INSTALLTIME}\n" +
		"[R\t%{REQUIRENEVRS}\n][P\t%{PROVIDENEVRS}\n]"
	out, err := exec.Command("rpm", "-qa", "--qf", q).Output()
	if err != nil {
		return fmt.Errorf("rpm -qa requires/provides: %w", err)
	}
	var cur *Package
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		switch {
		case f[0] == "@" && len(f) == 8:
			if f[1] == "gpg-pubkey-0:" || strings.HasPrefix(f[2], "gpg-pubkey") {
				cur = nil
				continue
			}
			it, _ := strconv.ParseInt(f[7], 10, 64)
			inv.Packages = append(inv.Packages, Package{NEVRA: f[1], Name: f[2], Epoch: f[3], Version: f[4], Release: f[5], Arch: f[6], InstallTime: it})
			cur = &inv.Packages[len(inv.Packages)-1]
		case cur != nil && f[0] == "R" && len(f) == 2 && !strings.HasPrefix(f[1], "rpmlib("):
			cur.Requires = append(cur.Requires, f[1])
		case cur != nil && f[0] == "P" && len(f) == 2:
			cur.Provides = append(cur.Provides, f[1])
		}
	}
	sort.Slice(inv.Packages, func(i, j int) bool { return inv.Packages[i].NEVRA < inv.Packages[j].NEVRA })
	return sc.Err()
}

func (inv *Inventory) loadFiles() error {
	// 배열 반복([...]) 안의 스칼라 태그는 %{=TAG} 로 써야 줄마다 반복된다
	out, err := exec.Command("rpm", "-qa", "--qf", "[%{FILENAMES}\t"+nevraRepeatFmt+"\n]").Output()
	if err != nil {
		return fmt.Errorf("rpm -qa filenames: %w", err)
	}
	dirCache := map[string]string{}
	canonDir := func(d string) string {
		if c, ok := dirCache[d]; ok {
			return c
		}
		c, err := filepath.EvalSymlinks(d)
		if err != nil {
			c = d
		}
		dirCache[d] = c
		return c
	}
	add := func(m map[string][]string, k, v string) {
		for _, x := range m[k] {
			if x == v {
				return
			}
		}
		m[k] = append(m[k], v)
	}

	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		path, nevra, ok := strings.Cut(sc.Text(), "\t")
		if !ok || !strings.HasPrefix(path, "/") {
			continue
		}
		add(inv.byPath, path, nevra)
		// /lib64 -> usr/lib64 처럼 디렉터리 심볼릭 링크를 정규화한 경로도 색인
		canon := filepath.Join(canonDir(filepath.Dir(path)), filepath.Base(path))
		if canon != path {
			add(inv.byPath, canon, nevra)
		}
		if id, ok := lstatRegular(path); ok {
			inv.byInode[id] = appendUnique(inv.byInode[id], nevra)
			if _, seen := inv.pathOf[id]; !seen {
				inv.pathOf[id] = canon
			}
		}
	}
	return sc.Err()
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// OwnersByPath 는 경로(또는 디렉터리 정규화 경로)의 소유 패키지.
func (inv *Inventory) OwnersByPath(p string) []string {
	if v := inv.byPath[p]; v != nil {
		return v
	}
	canon := filepath.Join(evalDir(filepath.Dir(p)), filepath.Base(p))
	return inv.byPath[canon]
}

// OwnersByInode 는 인벤토리 로드 시점에 같은 inode 였던 RPM 파일의 소유 패키지.
func (inv *Inventory) OwnersByInode(id procfs.DevIno) ([]string, string) {
	return inv.byInode[id], inv.pathOf[id]
}

func (inv *Inventory) FileCount() int { return len(inv.byPath) }

var evalCache sync.Map

func evalDir(d string) string {
	if c, ok := evalCache.Load(d); ok {
		return c.(string)
	}
	c, err := filepath.EvalSymlinks(d)
	if err != nil {
		c = d
	}
	evalCache.Store(d, c)
	return c
}
