// Package precheck 는 설계 5절의 사전 점검을 수행하고 CapabilityReport 를 만든다.
// 보안 설정·커널을 변경하지 않는다. 실패 시 이유를 남기고 unsupported/degraded 로 표시한다.
package precheck

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"

	"github.com/yeongki0944/ebpf-patch-precheck/code/agent/internal/bpfload"
)

const (
	StatusSupported   = "supported"
	StatusDegraded    = "degraded"
	StatusUnsupported = "unsupported"
)

type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Fatal  bool   `json:"fatal"` // 실패 시 eBPF 수집을 시작하지 않음
	Detail string `json:"detail,omitempty"`
}

type Report struct {
	Status      string    `json:"status"`
	CheckedAt   time.Time `json:"checked_at"`
	OSID        string    `json:"os_id"`
	OSVersion   string    `json:"os_version"`
	OSPretty    string    `json:"os_pretty"`
	Kernel      string    `json:"kernel"`
	Arch        string    `json:"arch"`
	BootID      string    `json:"boot_id"`
	MachineID   string    `json:"machine_id"`
	Checks      []Check   `json:"checks"`
	Attached    []string  `json:"attached_tracepoints,omitempty"`
	Reasons     []string  `json:"reasons,omitempty"`
	ProbeLoaded bool      `json:"-"`
}

func (r *Report) add(name string, ok, fatal bool, detail string) {
	r.Checks = append(r.Checks, Check{Name: name, OK: ok, Fatal: fatal, Detail: detail})
	if !ok {
		r.Reasons = append(r.Reasons, name+": "+detail)
	}
}

func readTrim(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func osRelease() map[string]string {
	m := map[string]string{}
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if ok {
			m[k] = strings.Trim(v, `"`)
		}
	}
	return m
}

// 지원 OS 목록 (설계 5절). 이름만으로 기능을 보장하지 않으며, 아래 실제 로드 점검이 최종 판정.
func osSupported(id, ver string) (bool, string) {
	switch {
	case id == "amzn" && ver == "2023":
		return true, "AL2023"
	case id == "rhel" && strings.HasPrefix(ver, "8."):
		return true, "RHEL 8"
	case id == "amzn" && ver == "2":
		return false, "AL2 는 후속 후보 (첫 버전 미지원)"
	case id == "rhel" && strings.HasPrefix(ver, "7"):
		return false, "RHEL 7 제외"
	}
	return false, "첫 버전 검증 대상 아님: " + id + " " + ver
}

func tracefsRoot() string {
	for _, p := range []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"} {
		if _, err := os.Stat(p + "/events"); err == nil {
			return p
		}
	}
	return ""
}

type Options struct {
	SpoolDir  string
	SkipLoad  bool // true 면 실제 프로그램 로드 시험을 생략 (run 에서 직접 로드할 때)
	AgentTGID uint32
}

// Run 은 점검을 수행한다. SkipLoad=false 면 실제 로드·연결 후 바로 해제한다.
func Run(o Options) *Report {
	var uts unix.Utsname
	_ = unix.Uname(&uts)
	osr := osRelease()
	r := &Report{
		CheckedAt: time.Now().UTC(),
		OSID:      osr["ID"],
		OSVersion: osr["VERSION_ID"],
		OSPretty:  osr["PRETTY_NAME"],
		Kernel:    unix.ByteSliceToString(uts.Release[:]),
		Arch:      unix.ByteSliceToString(uts.Machine[:]),
		BootID:    readTrim("/proc/sys/kernel/random/boot_id"),
		MachineID: readTrim("/etc/machine-id"),
	}

	ok, why := osSupported(r.OSID, r.OSVersion)
	r.add("os_supported", ok, true, why)
	r.add("arch_x86_64", runtime.GOARCH == "amd64" && r.Arch == "x86_64", true, r.Arch)
	r.add("boot_id", r.BootID != "", true, "")
	r.add("machine_id", r.MachineID != "", true, "/etc/machine-id")
	r.add("root", os.Geteuid() == 0, true, fmt.Sprintf("euid=%d", os.Geteuid()))

	// BTF: 파일 존재 + 실제 파싱
	if fi, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		r.add("btf_vmlinux", false, true, err.Error())
	} else if spec, err := btf.LoadKernelSpec(); err != nil {
		r.add("btf_vmlinux", false, true, "parse: "+err.Error())
	} else {
		_, terr := spec.AnyTypeByName("task_struct")
		r.add("btf_vmlinux", terr == nil, true, fmt.Sprintf("size=%d task_struct=%v", fi.Size(), terr == nil))
	}

	// lockdown (정보 제공, 변경하지 않음)
	if l := readTrim("/sys/kernel/security/lockdown"); l != "" {
		conf := strings.Contains(l, "[confidentiality]")
		r.add("lockdown", !conf, true, l)
	}

	// tracepoint 존재
	root := tracefsRoot()
	if root == "" {
		r.add("tracefs", false, true, "tracefs events 디렉터리 없음")
	} else {
		r.add("tracefs", true, true, root)
		for _, tp := range []string{"sched/sched_process_exec", "sched/sched_process_exit",
			"syscalls/sys_enter_openat", "syscalls/sys_exit_openat",
			"syscalls/sys_enter_mmap", "syscalls/sys_exit_mmap"} {
			_, err := os.Stat(root + "/events/" + tp + "/id")
			r.add("tp:"+tp, err == nil, true, errString(err))
		}
	}

	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rl); err == nil {
		r.add("memlock_info", true, false, fmt.Sprintf("cur=%d max=%d (로드 시 상향 시도)", rl.Cur, rl.Max))
	}

	// /proc 읽기
	_, err := os.ReadFile("/proc/1/maps")
	r.add("proc_read", err == nil, true, errString(err))

	// RPM DB
	out, err := exec.Command("rpm", "-q", "rpm").CombinedOutput()
	r.add("rpm_db", err == nil, true, strings.TrimSpace(string(out)))

	// spool
	if o.SpoolDir != "" {
		err := os.MkdirAll(o.SpoolDir, 0o700)
		if err == nil {
			var f *os.File
			f, err = os.CreateTemp(o.SpoolDir, ".precheck-*")
			if err == nil {
				f.Close()
				os.Remove(f.Name())
			}
		}
		r.add("spool_writable", err == nil, false, o.SpoolDir+" "+errString(err))
	}

	fatal := false
	for _, c := range r.Checks {
		if !c.OK && c.Fatal {
			fatal = true
		}
	}

	// 실제 로드·연결 시험 (검증기 통과, perf buffer 생성)
	if !fatal && !o.SkipLoad {
		p, err := bpfload.Load(o.AgentTGID, 64*1024)
		if err != nil {
			r.add("bpf_load_attach", false, true, err.Error())
			fatal = true
		} else {
			r.Attached = p.Attached
			r.add("bpf_load_attach", true, true, fmt.Sprintf("%d tracepoints", len(p.Attached)))
			for name, e := range p.Failed {
				r.add("optional:"+name, false, false, e)
			}
			p.Close()
		}
	}

	switch {
	case fatal:
		r.Status = StatusUnsupported
	case len(r.Reasons) > 0:
		r.Status = StatusDegraded
	default:
		r.Status = StatusSupported
	}
	return r
}

// AddLoadResult 는 run 모드에서 직접 로드한 결과를 반영한다.
func (r *Report) AddLoadResult(p *bpfload.Probe, err error) {
	if err != nil {
		r.add("bpf_load_attach", false, true, err.Error())
		r.Status = StatusUnsupported
		return
	}
	r.ProbeLoaded = true
	r.Attached = p.Attached
	r.add("bpf_load_attach", true, true, fmt.Sprintf("%d tracepoints", len(p.Attached)))
	for name, e := range p.Failed {
		r.add("optional:"+name, false, false, e)
		if r.Status == StatusSupported {
			r.Status = StatusDegraded
		}
	}
}

func (r *Report) Fatal() bool { return r.Status == StatusUnsupported }

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
