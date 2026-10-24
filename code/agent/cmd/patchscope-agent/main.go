// patchscope-agent: OS 패키지 패치 영향 분석용 수집 에이전트
//
//	patchscope-agent precheck [-json]        사전 점검만 (실제 로드·연결 시험 포함)
//	patchscope-agent run [flags]             수집 + spool + (설정 시) HTTPS 전송
//	patchscope-agent inventory -o FILE       RPM 인벤토리 JSON 출력
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/yeongki0944/ebpf-patch-precheck/code/agent/internal/bpfload"
	"github.com/yeongki0944/ebpf-patch-precheck/code/agent/internal/collector"
	"github.com/yeongki0944/ebpf-patch-precheck/code/agent/internal/model"
	"github.com/yeongki0944/ebpf-patch-precheck/code/agent/internal/precheck"
	"github.com/yeongki0944/ebpf-patch-precheck/code/agent/internal/rpminv"
	"github.com/yeongki0944/ebpf-patch-precheck/code/agent/internal/sender"
	"github.com/yeongki0944/ebpf-patch-precheck/code/agent/internal/spool"
	"github.com/yeongki0944/ebpf-patch-precheck/code/agent/internal/tasks"
)

var version = "dev" // -ldflags "-X main.version=..."

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s precheck|run|inventory [flags]\n", os.Args[0])
	os.Exit(2)
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "precheck":
		cmdPrecheck(os.Args[2:])
	case "run":
		cmdRun(os.Args[2:])
	case "inventory":
		cmdInventory(os.Args[2:])
	case "version":
		fmt.Println(version)
	default:
		usage()
	}
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func cmdPrecheck(args []string) {
	fs := flag.NewFlagSet("precheck", flag.ExitOnError)
	spoolDir := fs.String("spool", "/var/lib/patchscope/spool", "spool directory")
	asJSON := fs.Bool("json", false, "JSON output")
	_ = fs.Parse(args)

	r := precheck.Run(precheck.Options{SpoolDir: *spoolDir, AgentTGID: uint32(os.Getpid())})
	if *asJSON {
		printJSON(r)
	} else {
		fmt.Printf("status=%s os=%q kernel=%s arch=%s boot_id=%s\n", r.Status, r.OSPretty, r.Kernel, r.Arch, r.BootID)
		for _, c := range r.Checks {
			mark := "OK  "
			if !c.OK {
				mark = "FAIL"
				if !c.Fatal {
					mark = "WARN"
				}
			}
			fmt.Printf("  [%s] %-34s %s\n", mark, c.Name, c.Detail)
		}
		if len(r.Attached) > 0 {
			fmt.Printf("  attached: %s\n", strings.Join(r.Attached, ", "))
		}
	}
	if r.Fatal() {
		os.Exit(1)
	}
}

func cmdInventory(args []string) {
	fs := flag.NewFlagSet("inventory", flag.ExitOnError)
	out := fs.String("o", "-", "output file (- = stdout)")
	_ = fs.Parse(args)
	start := time.Now()
	inv, err := rpminv.Load()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("inventory %s: %d packages, %d paths (%s)", inv.ID, len(inv.Packages), inv.FileCount(), time.Since(start).Round(time.Millisecond))
	w := os.Stdout
	if *out != "-" {
		f, err := os.Create(*out)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		w = f
	}
	_ = json.NewEncoder(w).Encode(inv)
}

// sink 는 collector 출력을 spool 에 저장하고 sender 를 깨운다.
type sink struct {
	sp       *spool.Spool
	seq      *uint64
	wake     func()
	agent    string
	host     model.HostInfo
	planTool string
}

func (s *sink) next() uint64 { *s.seq++; return *s.seq }

func (s *sink) PutBatch(b *model.Batch) error {
	if err := s.sp.Put(s.next(), "batch", b.BatchID, b); err != nil {
		return err
	}
	s.wake()
	return nil
}

// PutHistory 는 dnf 거래 이력(읽기 전용 조회)을 spool 에 넣는다. 도구가 없거나 실패하면 건너뛴다.
func (s *sink) PutHistory(invID string) {
	if s.planTool == "" {
		return
	}
	if _, err := os.Stat(s.planTool); err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, s.planTool, "--history", "50", "-o", "-").Output()
	if err != nil || !json.Valid(out) {
		log.Printf("history export: %v", err)
		return
	}
	msg := map[string]any{"schema_version": model.SchemaVersion, "agent_id": s.agent, "host": s.host,
		"history": json.RawMessage(out)}
	if err := s.sp.Put(s.next(), "history", invID, msg); err != nil {
		log.Printf("spool history: %v", err)
		return
	}
	s.wake()
}

type inventoryMsg struct {
	SchemaVersion string             `json:"schema_version"`
	AgentID       string             `json:"agent_id"`
	Host          model.HostInfo     `json:"host"`
	Inventory     *rpminv.Inventory  `json:"inventory"`
}

func (s *sink) PutInventory(inv *rpminv.Inventory, host model.HostInfo) error {
	msg := inventoryMsg{SchemaVersion: model.SchemaVersion, AgentID: s.agent, Host: host, Inventory: inv}
	if err := s.sp.Put(s.next(), "inventory", inv.ID, msg); err != nil {
		return err
	}
	s.wake()
	// 인벤토리가 바뀌는 시점(시작·패치) 마다 거래 이력도 함께 보낸다 (언제·누가·무엇을)
	go s.PutHistory(inv.ID)
	return nil
}

func (s *sink) TakeDropped() ([]string, uint64) {
	d := s.sp.TakeDropped()
	return d.BatchIDs, d.Records
}

type capabilityMsg struct {
	SchemaVersion string            `json:"schema_version"`
	AgentID       string            `json:"agent_id"`
	AgentVersion  string            `json:"agent_version"`
	SessionID     string            `json:"session_id,omitempty"`
	Host          model.HostInfo    `json:"host"`
	Report        *precheck.Report  `json:"report"`
}

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	spoolDir := fs.String("spool", "/var/lib/patchscope/spool", "spool directory")
	spoolMax := fs.Int64("spool-max-mib", 1024, "spool size limit (MiB)")
	server := fs.String("server", "", "analysis server base URL (https://...). empty = spool only")
	caFile := fs.String("ca", "/etc/patchscope/ca.crt", "CA certificate for server verification")
	tokenFile := fs.String("token", "/etc/patchscope/agent.token", "agent token file (mode 600)")
	agentID := fs.String("agent-id", "", "agent id (default: hostname)")
	batchEvery := fs.Duration("batch", 10*time.Second, "batch interval")
	reconEvery := fs.Duration("reconcile", 60*time.Second, "/proc reconcile interval")
	invEvery := fs.Duration("inventory-check", 60*time.Second, "RPM inventory change check interval")
	// 이벤트 1000B. 256 pages 에서 burst 손실 1건 확인 -> 2MiB/CPU 기본
	perCPU := fs.Int("perf-pages", 512, "perf buffer pages per CPU (power of 2)")
	queue := fs.Int("queue", 65536, "user-space event queue size")
	excl := fs.String("exclude-paths", "/proc/,/sys/,/dev/", "comma separated path prefixes to drop for file events")
	exclComm := fs.String("exclude-comms", "", "comma separated comm names to drop for file_open")
	duration := fs.Duration("duration", 0, "stop after duration (0 = until signal)")
	planTool := fs.String("plan-tool", "/opt/patchscope/plan-export/patchscope-plan-export", "plan-export tool (resolve only). empty = disable task polling")
	taskEvery := fs.Duration("task-poll", 15*time.Second, "server task polling interval")
	_ = fs.Parse(args)

	if *agentID == "" {
		h, _ := os.Hostname()
		*agentID = h
	}

	// 1) 사전 점검 (로드는 아래에서 직접)
	rep := precheck.Run(precheck.Options{SpoolDir: *spoolDir, SkipLoad: true, AgentTGID: uint32(os.Getpid())})
	host := model.HostInfo{HostID: rep.MachineID, BootID: rep.BootID, Kernel: rep.Kernel, OSID: rep.OSID, OSVer: rep.OSVersion}
	host.Hostname, _ = os.Hostname()

	sp, err := spool.Open(*spoolDir, *spoolMax*1024*1024)
	if err != nil {
		log.Fatalf("spool: %v", err)
	}
	seq := sp.MaxSeq()
	sk := &sink{sp: sp, seq: &seq, wake: func() {}, agent: *agentID, host: host, planTool: *planTool}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if *duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *duration)
		defer cancel()
	}

	var snd *sender.Sender
	if *server != "" {
		snd, err = sender.New(sender.Config{ServerURL: *server, CAFile: *caFile, TokenFile: *tokenFile, AgentID: *agentID}, sp)
		if err != nil {
			log.Fatalf("sender: %v", err)
		}
		sk.wake = snd.Wake
	}
	sendDone := make(chan struct{})
	startSender := func() {
		if snd == nil {
			close(sendDone)
			return
		}
		go func() { snd.Run(ctx); close(sendDone) }()
	}

	putCap := func(sessionID string) {
		msg := capabilityMsg{SchemaVersion: model.SchemaVersion, AgentID: *agentID, AgentVersion: version, SessionID: sessionID, Host: host, Report: rep}
		if err := sp.Put(sk.next(), "capability", rep.Status, msg); err != nil {
			log.Printf("spool capability: %v", err)
		}
		sk.wake()
	}

	if rep.Fatal() {
		// 핵심 수집 불가: 이유를 보고하고 eBPF 수집을 시작하지 않음
		log.Printf("unsupported: %s", strings.Join(rep.Reasons, "; "))
		putCap("")
		startSender()
		if snd != nil {
			c2, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			<-c2.Done()
		}
		os.Exit(1)
	}

	// 2) eBPF 로드·연결 (이벤트 버퍼링 시작)
	probe, err := bpfload.Load(uint32(os.Getpid()), *perCPU*os.Getpagesize())
	rep.AddLoadResult(probe, err)
	if err != nil {
		log.Printf("bpf load failed: %v", err)
		putCap("")
		startSender()
		os.Exit(1)
	}
	defer probe.Close()
	log.Printf("attached: %s", strings.Join(probe.Attached, ", "))

	// 3) 인벤토리 (eBPF 연결 후 읽음. 에이전트 자식 rpm 프로세스는 커널에서 제외)
	t0 := time.Now()
	inv, err := rpminv.Load()
	if err != nil {
		log.Fatalf("inventory: %v", err)
	}
	log.Printf("inventory %s: %d packages, %d paths (%s)", inv.ID, len(inv.Packages), inv.FileCount(), time.Since(t0).Round(time.Millisecond))

	col := collector.New(collector.Config{
		AgentID:             *agentID,
		AgentVersion:        version,
		BatchInterval:       *batchEvery,
		ReconcileInterval:   *reconEvery,
		InventoryCheck:      *invEvery,
		ExecFollowupDelay:   300 * time.Millisecond,
		QueueSize:           *queue,
		MaxRecordsPerBatch:  20000,
		ExcludePathPrefixes: splitList(*excl),
		ExcludeComms:        splitList(*exclComm),
	}, probe, inv, host, sk, 0)

	putCap(col.SessionID())
	if err := sk.PutInventory(inv, host); err != nil {
		log.Printf("spool inventory: %v", err)
	}
	startSender()
	if snd != nil && *planTool != "" {
		if _, err := os.Stat(*planTool); err == nil {
			p := &tasks.Poller{Client: snd.Client(), Server: *server, Token: snd.Token(), AgentID: *agentID,
				Tool: *planTool, Interval: *taskEvery}
			go p.Run(ctx)
			log.Printf("plan task polling enabled (%s, every %s)", *planTool, *taskEvery)
		} else {
			log.Printf("plan tool %s not found: plan task polling disabled", *planTool)
		}
	}
	log.Printf("session %s status=%s server=%q", col.SessionID(), rep.Status, *server)

	if err := col.Run(ctx); err != nil {
		log.Printf("collector: %v", err)
	}
	t := col.Totals()
	log.Printf("stopped: events=%d loss_free=%v perf_lost=%d queue_drop=%d kernel_output_fail=%d",
		t.EventsReceived, t.LossFree(), t.PerfLost, t.QueueDrop, t.KernelOutputFail)
	stop()
	<-sendDone
}

func splitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}
