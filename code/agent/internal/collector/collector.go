// Package collector 는 eBPF 이벤트와 /proc 스냅샷을 결합해 배치를 만든다.
//
// 순서 (설계 7.1): eBPF 연결 → 이벤트 버퍼링 시작 → 초기 /proc 스냅샷 → 버퍼 이벤트 재조정.
// 모든 상태는 단일 goroutine(loop)에서만 변경한다.
package collector

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"

	"github.com/yeongki0944/ebpf-patch-precheck/code/agent/internal/bpfload"
	"github.com/yeongki0944/ebpf-patch-precheck/code/agent/internal/model"
	"github.com/yeongki0944/ebpf-patch-precheck/code/agent/internal/procfs"
	"github.com/yeongki0944/ebpf-patch-precheck/code/agent/internal/rpminv"
)

type Config struct {
	AgentID             string
	AgentVersion        string
	BatchInterval       time.Duration
	ReconcileInterval   time.Duration
	InventoryCheck      time.Duration
	ExecFollowupDelay   time.Duration
	QueueSize           int
	MaxRecordsPerBatch  int
	ExcludePathPrefixes []string
	ExcludeComms        []string
}

// Sink 는 완성된 배치·인벤토리를 받는다 (spool). TakeDropped 는 spool 한도로 지운 배치 정보.
type Sink interface {
	PutBatch(b *model.Batch) error
	PutInventory(inv *rpminv.Inventory, host model.HostInfo) error
	TakeDropped() (batchIDs []string, records uint64)
}

type Collector struct {
	cfg   Config
	probe *bpfload.Probe
	sink  Sink
	host  model.HostInfo

	inv   *rpminv.Inventory
	res   *resolver
	procs *procTable

	sessionID string
	seq       uint64
	bootNs    int64 // CLOCK_REALTIME - CLOCK_BOOTTIME (UTC 환산)
	monoNs    int64 // CLOCK_REALTIME - CLOCK_MONOTONIC

	queue      chan []byte
	queueDrop  atomic.Uint64
	perfLost   atomic.Uint64
	decodeFail uint64

	followups chan followup
	fuDrop    atomic.Uint64

	records     []model.Record
	agg         map[aggKey]int // records 내 위치
	windowStart time.Time
	delta       model.Counters
	total       model.Counters
	lastKernel  [bpfload.NumStats]uint64
	droppedIDs  []string
}

type aggKey struct {
	proc, kind, path, dev string
	ino                   uint64
	ok                    bool
	errno                 int
}

type followup struct {
	pid        uint32
	startTicks uint64
}

func New(cfg Config, probe *bpfload.Probe, inv *rpminv.Inventory, host model.HostInfo, sink Sink, seqStart uint64) *Collector {
	c := &Collector{
		cfg:       cfg,
		probe:     probe,
		sink:      sink,
		host:      host,
		inv:       inv,
		res:       newResolver(inv),
		procs:     newProcTable(host.HostID, host.BootID),
		sessionID: newID(),
		seq:       seqStart,
		queue:     make(chan []byte, cfg.QueueSize),
		followups: make(chan followup, 4096),
		agg:       map[aggKey]int{},
	}
	c.calibrateClocks()
	return c
}

func (c *Collector) SessionID() string { return c.sessionID }

func newID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func selfPID() int { return os.Getpid() }

func (c *Collector) calibrateClocks() {
	var rt, bt, mt unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_REALTIME, &rt)
	_ = unix.ClockGettime(unix.CLOCK_BOOTTIME, &bt)
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &mt)
	c.bootNs = rt.Nano() - bt.Nano()
	c.monoNs = rt.Nano() - mt.Nano()
}

func (c *Collector) monoToUTC(ns uint64) time.Time { return time.Unix(0, int64(ns)+c.monoNs).UTC() }

// readLoop 는 perf buffer 를 비우는 것만 한다 (처리는 loop). 큐가 차면 손실로 집계.
func (c *Collector) readLoop() {
	for {
		rec, err := c.probe.Reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				close(c.queue)
				return
			}
			continue
		}
		if rec.LostSamples > 0 {
			c.perfLost.Add(rec.LostSamples)
			continue
		}
		select {
		case c.queue <- rec.RawSample:
		default:
			c.queueDrop.Add(1)
		}
	}
}

// Run 은 ctx 가 끝날 때까지 수집한다. 종료 시 마지막 배치를 flush 한다.
func (c *Collector) Run(ctx context.Context) error {
	go c.readLoop()

	// eBPF 는 이미 연결되어 큐에 쌓이는 중. 이제 초기 스냅샷.
	c.windowStart = time.Now().UTC()
	c.addAgentNote("session_start", fmt.Sprintf("inventory=%s packages=%d files=%d", c.inv.ID, len(c.inv.Packages), c.inv.FileCount()))
	n := c.snapshot(model.SourceSnapshot)
	log.Printf("initial snapshot: %d processes", n)

	batchT := time.NewTicker(c.cfg.BatchInterval)
	reconT := time.NewTicker(c.cfg.ReconcileInterval)
	invT := time.NewTicker(c.cfg.InventoryCheck)
	defer batchT.Stop()
	defer reconT.Stop()
	defer invT.Stop()

	for {
		select {
		case <-ctx.Done():
			c.probe.Reader.Close()
			for raw := range c.queue { // 남은 이벤트 처리
				c.handle(raw)
			}
			c.flush("shutdown", true)
			return nil
		case raw, ok := <-c.queue:
			if !ok {
				c.flush("reader_closed", true)
				return errors.New("perf reader closed")
			}
			c.handle(raw)
			if len(c.records) >= c.cfg.MaxRecordsPerBatch {
				c.flush("size", false)
			}
		case fu := <-c.followups:
			c.execFollowup(fu)
		case <-batchT.C:
			c.flush("interval", false)
		case <-reconT.C:
			c.snapshot(model.SourceSnapshot)
		case <-invT.C:
			c.checkInventory()
		}
	}
}

func (c *Collector) addAgentNote(kind, note string) {
	c.records = append(c.records, model.Record{Kind: kind, Source: model.SourceAgent, TsUTC: time.Now().UTC(), Note: note})
}

// ---------------------------------------------------------------- 스냅샷

// snapshot 은 처음 보는 프로세스 인스턴스만 exe·maps·fd 를 기록한다 (주기적 재조정 겸용).
func (c *Collector) snapshot(source string) int {
	pids, err := procfs.ListPIDs()
	if err != nil {
		return 0
	}
	self := uint32(selfPID())
	n := 0
	for _, pid := range pids {
		if pid == self {
			continue
		}
		st, err := procfs.ReadStat(pid)
		if err != nil {
			continue // 그 사이 종료
		}
		p, isNew := c.procs.get(pid, st.StartTicks)
		if !isNew {
			continue
		}
		c.recordProcState(p, st, source)
		n++
	}
	return n
}

// recordProcState 는 프로세스의 현재 exe·maps·fd 를 레코드로 남긴다.
// 읽는 도중 PID 가 재사용되면(start 불일치) 버리고 snapshot_missed 를 남긴다.
func (c *Collector) recordProcState(p *procInfo, st procfs.Stat, source string) {
	now := time.Now().UTC()
	parentTicks := uint64(0)
	if pst, err := procfs.ReadStat(st.PPID); err == nil {
		parentTicks = pst.StartTicks
	}
	c.procs.fillUnit(p, st.PPID, parentTicks)
	ref := model.ProcRef{PID: p.pid, StartTicks: p.startTicks, Key: p.key}
	base := model.Record{Source: source, TsUTC: now, Proc: ref, PPID: st.PPID, Comm: st.Comm,
		Unit: p.unit, UnitSource: p.unitSource}
	if parentTicks != 0 {
		base.ParentKey = c.procs.keyOf(st.PPID, parentTicks)
	}
	if uid, ok := procfs.ReadUID(p.pid); ok {
		base.UID = &uid
	}

	exe := procfs.ReadExe(p.pid)
	maps, merr := procfs.ReadMaps(p.pid)
	fds, _ := procfs.ReadFDs(p.pid)
	if st2, err := procfs.ReadStat(p.pid); err != nil || st2.StartTicks != p.startTicks {
		c.missed(base, "process exited or pid reused during /proc read")
		return
	}
	if !exe.OK && merr != nil {
		// 커널 스레드(exe 없음)는 기록하지 않음
		if isKernelThread(p.pid) {
			return
		}
		c.missed(base, "exe/maps unreadable")
		return
	}

	r := base
	r.Kind = model.KindProcess
	if exe.OK {
		r.File = c.res.fileRef(exe.Path, model.PathKernel, exe.ID, exe.Deleted, p.otherNS)
		c.res.remember(exe.ID, exe.Path)
	} else {
		r.Note = "exe unreadable"
	}
	if p.otherNS {
		r.Note = strings.TrimSpace(r.Note + " other_mount_namespace: rpm ownership not resolved")
	}
	c.records = append(c.records, r)

	p.mapsIdx = map[procfs.DevIno]string{}
	p.mapsLoaded = merr == nil
	for _, m := range maps {
		mr := base
		mr.Kind = model.KindMapped
		mr.Perms = m.Perms
		mr.File = c.res.fileRef(m.Path, model.PathKernel, m.ID, m.Deleted, p.otherNS)
		c.records = append(c.records, mr)
		path := m.Path
		if m.Deleted {
			path += deletedMark
		} else {
			c.res.remember(m.ID, m.Path)
		}
		p.mapsIdx[m.ID] = path
	}
	for _, f := range fds {
		if c.excludedPath(f.Path) {
			continue
		}
		fr := base
		fr.Kind = model.KindOpenFD
		fr.File = c.res.fileRef(f.Path, model.PathKernel, f.ID, f.Deleted, p.otherNS)
		c.records = append(c.records, fr)
	}
}

func isKernelThread(pid uint32) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	return err == nil && len(b) == 0
}

func (c *Collector) missed(base model.Record, why string) {
	base.Kind = model.KindSnapMissed
	base.Note = why
	c.records = append(c.records, base)
	c.delta.SnapshotMissed++
}

// execFollowup 은 exec 직후 잠시 뒤 maps 를 읽어 로더가 매핑한 라이브러리를 보완한다.
// 이미 종료된 단기 프로세스는 snapshot_missed (실행·파일 이벤트는 그대로 유지).
func (c *Collector) execFollowup(fu followup) {
	p, ok := c.procs.byPID[fu.pid]
	if !ok || p.startTicks != fu.startTicks || p.exited {
		return
	}
	st, err := procfs.ReadStat(fu.pid)
	if err != nil || st.StartTicks != fu.startTicks {
		c.missed(model.Record{Source: model.SourceFollowup, TsUTC: time.Now().UTC(),
			Proc: model.ProcRef{PID: fu.pid, StartTicks: fu.startTicks, Key: p.key}}, "exited before maps read")
		return
	}
	c.recordProcState(p, st, model.SourceFollowup)
}

// ---------------------------------------------------------------- 이벤트

func (c *Collector) handle(raw []byte) {
	var e bpfload.Event
	if err := bpfload.Decode(raw, &e); err != nil {
		c.decodeFail++
		return
	}
	c.delta.EventsReceived++

	startTicks := procfs.NsToTicks(e.StartBootNs)
	p, isNew := c.procs.get(e.TGID, startTicks)
	ref := model.ProcRef{PID: e.TGID, StartTicks: startTicks, Key: p.key}
	uid := e.UID
	rec := model.Record{Source: model.SourceEBPF, TsMonoNs: e.TsNs, TsUTC: c.monoToUTC(e.TsNs),
		Proc: ref, TID: e.PID, PPID: e.PPID, Comm: e.Comm, UID: &uid}
	if e.ParentStartNs != 0 {
		rec.ParentKey = c.procs.keyOf(e.PPID, procfs.NsToTicks(e.ParentStartNs))
	}
	if u := unitFromEvent(e); u != "" {
		// 커널이 이벤트 시점에 본 cgroup. 프로세스가 다른 unit 으로 옮겨질 수 있어 이벤트마다 갱신
		p.unit, p.unitSource = u, "cgroup_kernel"
		if isNew {
			c.procs.fillNS(p)
		}
	} else if isNew || p.unitSource == "" {
		c.procs.fillUnit(p, e.PPID, procfs.NsToTicks(e.ParentStartNs))
	}
	rec.Unit, rec.UnitSource = p.unit, p.unitSource
	id := procfs.DevIno{Dev: procfs.DevFromKernel(e.Dev), Ino: e.Ino}

	switch e.Type {
	case bpfload.EvExec:
		rec.Kind = model.KindExec
		// 같은 PID 에서 exec 하면 이미지가 바뀜: maps 색인 초기화
		p.mapsIdx, p.mapsLoaded = nil, false
		rec.File = c.resolveExec(e, id, p)
		c.records = append(c.records, rec)
		// 로더가 라이브러리를 매핑할 시간을 두고 maps 를 읽음 (loop 를 막지 않도록 타이머 사용)
		fu := followup{pid: e.TGID, startTicks: startTicks}
		time.AfterFunc(c.cfg.ExecFollowupDelay, func() {
			select {
			case c.followups <- fu:
			default:
				c.fuDrop.Add(1)
			}
		})

	case bpfload.EvExit:
		rec.Kind = model.KindExit
		code := int((e.Ret >> 8) & 0xff)
		rec.ExitCode = &code
		if sig := int(e.Ret & 0x7f); sig != 0 {
			rec.Signal = &sig
		}
		p.exited = true
		c.records = append(c.records, rec)

	case bpfload.EvOpen:
		rec.Kind = model.KindOpen
		rec.Flags = e.Flags
		okv := e.Ret >= 0
		rec.OK = &okv
		if !okv {
			rec.Errno = int(-e.Ret)
		}
		if c.excludedComm(e.Comm) {
			c.delta.Filtered++
			return
		}
		f := c.resolveOpen(e, id, okv, p)
		if c.excludedPath(f.Path) || c.excludedPath(f.RequestedPath) {
			c.delta.Filtered++
			return
		}
		rec.File = f
		c.appendAggregated(rec)

	case bpfload.EvMmap:
		rec.Kind = model.KindMmap
		rec.Flags, rec.Prot = e.Flags, e.Prot
		okv := !(e.Ret < 0 && e.Ret >= -4095)
		rec.OK = &okv
		if !okv {
			rec.Errno = int(-e.Ret)
		}
		if !e.HasIdent {
			rec.File = &model.FileRef{PathStatus: model.PathUnresolved, Ownership: model.OwnUnknown}
			if okv {
				c.delta.IdentFail++
			}
		} else {
			rec.File = c.resolveByIDEv(e, id, p)
		}
		c.appendAggregated(rec)
	}
}

// unitFromEvent 는 이벤트 시점의 cgroup leaf 이름으로 systemd unit 을 정한다.
// (단기 프로세스도 종료 전에 커널에서 읽으므로 /proc/PID/cgroup 보다 정확)
func unitFromEvent(e bpfload.Event) string {
	for _, n := range []string{e.CgroupDfl, e.CgroupPids} {
		if isUnitName(n) {
			return n
		}
	}
	return ""
}

func isUnitName(n string) bool {
	for _, suf := range []string{".service", ".scope", ".socket", ".mount", ".timer"} {
		if strings.HasSuffix(n, suf) {
			return true
		}
	}
	return false
}

func (c *Collector) resolveExec(e bpfload.Event, id procfs.DevIno, p *procInfo) *model.FileRef {
	if !e.HasIdent {
		return &model.FileRef{RequestedPath: e.Path, PathStatus: model.PathRequested, Ownership: model.OwnUnknown}
	}
	// 실행 경로(인터프리터 실행 시 스크립트 경로일 수 있음)가 실제 exe inode 와 일치할 때만 확정
	if strings.HasPrefix(e.Path, "/") && verify(e.Path, id) {
		real := e.Path
		if rp, err := filepath.EvalSymlinks(e.Path); err == nil && verify(rp, id) {
			real = rp
		}
		c.res.remember(id, real)
		f := c.res.fileRef(real, model.PathVerified, id, false, p.otherNS)
		if real != e.Path {
			f.RequestedPath = e.Path
		}
		return f
	}
	if exe := procfs.ReadExe(e.TGID); exe.OK && exe.ID == id {
		f := c.res.fileRef(exe.Path, model.PathKernel, id, exe.Deleted, p.otherNS)
		f.RequestedPath = e.Path
		return f
	}
	f := c.resolveByIDEv(e, id, p)
	f.RequestedPath = e.Path
	return f
}

func (c *Collector) resolveOpen(e bpfload.Event, id procfs.DevIno, ok bool, p *procInfo) *model.FileRef {
	abs, absOK := procfs.ResolveRequested(e.TGID, e.DFD, e.Path)
	if !ok || !e.HasIdent {
		f := &model.FileRef{RequestedPath: e.Path, PathStatus: model.PathRequested, Ownership: model.OwnUnknown}
		if absOK {
			f.RequestedPath = abs
		}
		if ok {
			c.delta.IdentFail++
		}
		return f
	}
	// 상대 경로(dirfd 기준)는 사용자 공간에서 dirfd 가 이미 닫혀 있을 수 있으므로 커널 경로를 먼저 사용
	if !strings.HasPrefix(e.Path, "/") {
		if f := c.kpathRef(e, id, p); f != nil {
			f.RequestedPath = e.Path
			return f
		}
	}
	if absOK && verify(abs, id) {
		// 심볼릭 링크(/lib64/libc.so.6 등)는 실제 파일 경로로 확정, 요청 경로는 따로 보존
		real := abs
		if rp, err := filepath.EvalSymlinks(abs); err == nil && verify(rp, id) {
			real = rp
		}
		c.res.remember(id, real)
		f := c.res.fileRef(real, model.PathVerified, id, false, p.otherNS)
		if real != e.Path {
			f.RequestedPath = e.Path
		}
		return f
	}
	f := c.resolveByIDEv(e, id, p)
	f.RequestedPath = e.Path
	return f
}

// kpathRef 는 커널이 이벤트 시점에 본 dentry 경로를 후보로 사용한다.
//   - 호스트 mount namespace 프로세스만 (다른 ns 의 루트 기준 경로는 호스트 경로가 아님)
//   - 지금 stat 한 dev/ino 가 이벤트와 같을 때만 확정 (교체·삭제된 파일 혼합 방지)
//   - 이벤트 시점에 이미 삭제(nlink=0)였다면 deleted 로 표시하고 현재 경로로 해석하지 않음
func (c *Collector) kpathRef(e bpfload.Event, id procfs.DevIno, p *procInfo) *model.FileRef {
	if e.KPath == "" || p.otherNS {
		return nil
	}
	if e.KFlags&bpfload.KFNlinkZero != 0 {
		return c.res.fileRef(e.KPath, model.PathKernel, id, true, p.otherNS)
	}
	if !verify(e.KPath, id) {
		return nil
	}
	c.res.remember(id, e.KPath)
	return c.res.fileRef(e.KPath, model.PathKernel, id, false, p.otherNS)
}

// resolveByID: 커널 경로 → 프로세스 maps → 세션 inode 색인 → 인벤토리 inode 순서로 경로를 찾는다.
func (c *Collector) resolveByID(id procfs.DevIno, p *procInfo) *model.FileRef {
	return c.resolveByIDEv(bpfload.Event{}, id, p)
}

func (c *Collector) resolveByIDEv(e bpfload.Event, id procfs.DevIno, p *procInfo) *model.FileRef {
	if f := c.kpathRef(e, id, p); f != nil {
		return f
	}
	if path, del, ok := c.procs.lookupMapped(p, id); ok {
		return c.res.fileRef(path, model.PathKernel, id, del, p.otherNS)
	}
	path, status := c.res.byID(id)
	return c.res.fileRef(path, status, id, false, p.otherNS)
}

// appendAggregated 는 배치 내 동일 (프로세스, 종류, 파일, 결과)를 하나로 합친다.
func (c *Collector) appendAggregated(r model.Record) {
	k := aggKey{proc: r.Proc.Key, kind: r.Kind, errno: r.Errno}
	if r.OK != nil {
		k.ok = *r.OK
	}
	if r.File != nil {
		k.path, k.dev, k.ino = r.File.Path+"|"+r.File.RequestedPath, r.File.Dev, r.File.Ino
	}
	if i, ok := c.agg[k]; ok {
		ex := &c.records[i]
		ex.Count++
		t := r.TsUTC
		ex.LastTsUTC = &t
		c.delta.Aggregated++
		return
	}
	r.Count = 1
	c.agg[k] = len(c.records)
	c.records = append(c.records, r)
}

func (c *Collector) excludedPath(p string) bool {
	if p == "" {
		return false
	}
	for _, pre := range c.cfg.ExcludePathPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

func (c *Collector) excludedComm(comm string) bool {
	for _, x := range c.cfg.ExcludeComms {
		if comm == x {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- 인벤토리

// checkInventory 는 RPM 목록이 바뀌었으면(패치 등) 인벤토리를 다시 읽고 서버로 보낸다.
// 이전 배치는 이전 inventory_id 로 이미 확정되어 있으므로 매핑이 보존된다.
func (c *Collector) checkInventory() {
	id, _, err := rpminv.CurrentID()
	if err != nil || id == c.inv.ID {
		return
	}
	c.flush("inventory_change", false)
	inv, err := rpminv.Load()
	if err != nil {
		log.Printf("inventory reload: %v", err)
		return
	}
	old := c.inv.ID
	c.inv = inv
	c.res.setInventory(inv)
	c.res.idx = map[procfs.DevIno]string{}
	if err := c.sink.PutInventory(inv, c.host); err != nil {
		log.Printf("spool inventory: %v", err)
	}
	c.records = append(c.records, model.Record{Kind: model.KindInventory, Source: model.SourceAgent,
		TsUTC: time.Now().UTC(), Note: fmt.Sprintf("%s -> %s", old, inv.ID)})
	log.Printf("inventory changed %s -> %s", old, inv.ID)
}

// ---------------------------------------------------------------- 배치

func (c *Collector) collectCounters() {
	if ks, err := c.probe.KernelStats(); err == nil {
		c.delta.KernelOutputFail += ks[0] - c.lastKernel[0]
		c.delta.InflightFull += ks[1] - c.lastKernel[1]
		c.delta.IdentFail += ks[2] - c.lastKernel[2]
		c.delta.PathFail += ks[3] - c.lastKernel[3]
		c.lastKernel = ks
	}
	c.delta.PerfLost += c.perfLost.Swap(0)
	c.delta.QueueDrop += c.queueDrop.Swap(0)
	c.delta.FollowupDrop += c.fuDrop.Swap(0)
	c.delta.DecodeFail += c.decodeFail
	c.decodeFail = 0
	ids, n := c.sink.TakeDropped()
	c.delta.SpoolDropBatches += uint64(len(ids))
	c.delta.SpoolDropRecords += n
	c.droppedIDs = append(c.droppedIDs, ids...)
}

// Policy 는 배치에 기록되는 수집 정책.
func (c *Collector) Policy() model.FilterPolicy {
	return model.FilterPolicy{
		ExcludePathPrefixes: c.cfg.ExcludePathPrefixes,
		ExcludeComms:        c.cfg.ExcludeComms,
		Aggregation:         "file_open/file_mmap: per batch by (process, file, result), count + first/last ts",
	}
}

func (c *Collector) flush(reason string, final bool) {
	c.collectCounters()
	if len(c.records) == 0 && c.delta == (model.Counters{}) && !final {
		c.windowStart = time.Now().UTC()
		return
	}
	c.seq++
	b := &model.Batch{
		SchemaVersion: model.SchemaVersion,
		AgentID:       c.cfg.AgentID,
		AgentVersion:  c.cfg.AgentVersion,
		BatchID:       fmt.Sprintf("%s-%d", c.sessionID, c.seq),
		SessionID:     c.sessionID,
		Seq:           c.seq,
		Host:          c.host,
		InventoryID:   c.inv.ID,
		CreatedAt:     time.Now().UTC(),
		WindowStart:   c.windowStart,
		Reason:        reason,
		Policy:        c.Policy(),
		Records:       c.records,
	}
	b.Delta = c.delta
	b.Total = c.total
	b.Total.Add(c.delta)
	b.DroppedBatchIDs = c.droppedIDs
	b.Complete = b.Delta.LossFree()
	if err := c.sink.PutBatch(b); err != nil {
		log.Printf("spool batch %s: %v (records kept for next batch)", b.BatchID, err)
		c.seq--
		return
	}
	c.total = b.Total
	c.droppedIDs = nil
	c.records = nil
	c.agg = map[aggKey]int{}
	c.delta = model.Counters{}
	c.windowStart = b.CreatedAt
	c.procs.sweep()
}

// Totals 는 현재까지 누적 카운터 (status 출력용).
func (c *Collector) Totals() model.Counters { return c.total }
