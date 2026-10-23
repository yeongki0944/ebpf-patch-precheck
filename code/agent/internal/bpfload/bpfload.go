// Package bpfload 는 내장된 CO-RE 오브젝트를 로드·연결하고 perf reader 를 연다.
package bpfload

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// make 가 bpf/patchscope.bpf.c 를 컴파일해 이 위치에 둔다.
//
//go:embed patchscope.bpf.o
var object []byte

type tracepoint struct {
	group, name, prog string
}

// 필수: 하나라도 실패하면 핵심 수집 불가(unsupported)
var required = []tracepoint{
	{"sched", "sched_process_exec", "tp_exec"},
	{"sched", "sched_process_exit", "tp_exit"},
	{"syscalls", "sys_enter_openat", "tp_enter_openat"},
	{"syscalls", "sys_exit_openat", "tp_exit_openat"},
	{"syscalls", "sys_enter_mmap", "tp_enter_mmap"},
	{"syscalls", "sys_exit_mmap", "tp_exit_mmap"},
}

// 선택: 실패 시 degraded (레거시 open(2) 경로 누락)
var optional = []tracepoint{
	{"syscalls", "sys_enter_open", "tp_enter_open"},
	{"syscalls", "sys_exit_open", "tp_exit_open"},
}

const NumStats = 4 // patchscope.h PS_STAT_MAX

type Probe struct {
	coll     *ebpf.Collection
	links    []link.Link
	Reader   *perf.Reader
	Attached []string
	Failed   map[string]string // 선택 tracepoint 의 연결 실패 사유
}

// Load 는 메모리 잠금 한도 해제, 프로그램 로드(검증기 통과), tracepoint 연결까지 수행한다.
func Load(agentTGID uint32, perCPUBytes int) (*Probe, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("memlock: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return nil, fmt.Errorf("parse object: %w", err)
	}
	v, ok := spec.Variables["agent_tgid"]
	if !ok {
		return nil, errors.New("agent_tgid variable missing in object")
	}
	if err := v.Set(agentTGID); err != nil {
		return nil, fmt.Errorf("set agent_tgid: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("verifier: %+v", ve)
		}
		return nil, fmt.Errorf("load: %w", err)
	}
	p := &Probe{coll: coll, Failed: map[string]string{}}

	attach := func(t tracepoint) error {
		prog := coll.Programs[t.prog]
		if prog == nil {
			return fmt.Errorf("program %s missing", t.prog)
		}
		l, err := link.Tracepoint(t.group, t.name, prog, nil)
		if err != nil {
			return err
		}
		p.links = append(p.links, l)
		p.Attached = append(p.Attached, t.group+"/"+t.name)
		return nil
	}
	for _, t := range required {
		if err := attach(t); err != nil {
			p.Close()
			return nil, fmt.Errorf("attach %s/%s: %w", t.group, t.name, err)
		}
	}
	for _, t := range optional {
		if err := attach(t); err != nil {
			p.Failed[t.group+"/"+t.name] = err.Error()
		}
	}

	p.Reader, err = perf.NewReader(coll.Maps["events"], perCPUBytes)
	if err != nil {
		p.Close()
		return nil, fmt.Errorf("perf reader: %w", err)
	}
	return p, nil
}

// KernelStats 는 per-CPU 카운터의 합계 (patchscope.h enum ps_stat 순서).
func (p *Probe) KernelStats() ([NumStats]uint64, error) {
	var out [NumStats]uint64
	m := p.coll.Maps["stats"]
	for k := uint32(0); k < NumStats; k++ {
		var vals []uint64
		if err := m.Lookup(k, &vals); err != nil {
			return out, err
		}
		for _, v := range vals {
			out[k] += v
		}
	}
	return out, nil
}

func (p *Probe) Close() {
	if p.Reader != nil {
		p.Reader.Close()
	}
	for _, l := range p.links {
		l.Close()
	}
	if p.coll != nil {
		p.coll.Close()
	}
}
