// Package tasks 는 서버의 "패치 계획 계산" 요청을 가져와(pull) 실행한다.
//
// 보안 경계
//   - 에이전트가 서버로 나가는 HTTPS 만 사용 (서버 → 에이전트 접속 없음)
//   - 실행 가능한 동작은 고정된 두 가지: list_updates, resolve_plan
//     둘 다 dnf 거래를 "계산"만 하고 설치·제거·재시작은 하지 않는다
//   - 패키지 이름·releasever 는 허용 문자 검사 후 인자 배열로 전달 (셸 해석 없음)
//   - 임의 명령·경로·옵션은 받지 않는다
package tasks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const (
	KindListUpdates = "list_updates"
	KindResolvePlan = "resolve_plan"
	maxPackages     = 200
	runTimeout      = 10 * time.Minute
)

var (
	pkgRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	relRe = regexp.MustCompile(`^(latest|[0-9][0-9.]{0,31})$`)
)

type Task struct {
	ID         int64    `json:"id"`
	Kind       string   `json:"kind"`
	Packages   []string `json:"packages"`
	Kernel     bool     `json:"kernel"`
	Releasever string   `json:"releasever"`
}

// Validate 는 서버가 보낸 요청을 허용 목록으로 검사한다.
func (t Task) Validate() error {
	switch t.Kind {
	case KindListUpdates, KindResolvePlan:
	default:
		return fmt.Errorf("unsupported task kind %q", t.Kind)
	}
	if len(t.Packages) > maxPackages {
		return fmt.Errorf("too many packages")
	}
	for _, p := range t.Packages {
		if !pkgRe.MatchString(p) {
			return fmt.Errorf("invalid package name %q", p)
		}
	}
	if t.Releasever != "" && !relRe.MatchString(t.Releasever) {
		return fmt.Errorf("invalid releasever %q", t.Releasever)
	}
	return nil
}

// Args 는 plan-export 인자 배열. "--" 뒤에 패키지 이름을 두어 옵션으로 해석되지 않게 한다.
func (t Task) Args() []string {
	var a []string
	if t.Kind == KindListUpdates {
		a = append(a, "--list-updates")
	}
	if t.Kernel {
		a = append(a, "--kernel")
	}
	if t.Releasever != "" {
		a = append(a, "--releasever", t.Releasever)
	}
	a = append(a, "-o", "-")
	if t.Kind == KindResolvePlan && len(t.Packages) > 0 {
		a = append(a, "--")
		a = append(a, t.Packages...)
	}
	return a
}

type Poller struct {
	Client   *http.Client
	Server   string
	Token    string
	AgentID  string
	Tool     string // patchscope-plan-export 경로
	Interval time.Duration
}

func (p *Poller) req(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	r, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(p.Server, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Authorization", "Bearer "+p.Token)
	r.Header.Set("X-PatchScope-Agent", p.AgentID)
	r.Header.Set("X-PatchScope-Schema", "1")
	r.Header.Set("Content-Type", "application/json")
	return p.Client.Do(r)
}

// Run 은 Interval 마다 서버에 대기 중인 요청을 묻고, 하나씩 실행해 결과를 올린다.
func (p *Poller) Run(ctx context.Context) {
	t := time.NewTicker(p.Interval)
	defer t.Stop()
	for {
		if err := p.once(ctx); err != nil {
			log.Printf("tasks: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (p *Poller) once(ctx context.Context) error {
	resp, err := p.req(ctx, http.MethodPost, "/api/v1/tasks/claim", []byte("{}"))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("claim http %d: %s", resp.StatusCode, b)
	}
	var task Task
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&task); err != nil {
		return fmt.Errorf("claim decode: %w", err)
	}
	result, runErr := p.execute(ctx, task)
	return p.report(ctx, task.ID, result, runErr)
}

func (p *Poller) execute(ctx context.Context, t Task) (json.RawMessage, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	c, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()
	cmd := exec.CommandContext(c, p.Tool, t.Args()...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	log.Printf("tasks: run #%d %s packages=%d kernel=%v", t.ID, t.Kind, len(t.Packages), t.Kernel)
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if len(msg) > 2000 {
			msg = msg[len(msg)-2000:]
		}
		return nil, fmt.Errorf("%v: %s", err, msg)
	}
	if !json.Valid(out.Bytes()) {
		return nil, fmt.Errorf("tool output is not json")
	}
	return out.Bytes(), nil
}

func (p *Poller) report(ctx context.Context, id int64, result json.RawMessage, runErr error) error {
	body := map[string]any{"ok": runErr == nil}
	if runErr != nil {
		body["error"] = runErr.Error()
	} else {
		body["result"] = result
	}
	b, _ := json.Marshal(body)
	resp, err := p.req(ctx, http.MethodPost, fmt.Sprintf("/api/v1/tasks/%d/result", id), b)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("result http %d", resp.StatusCode)
	}
	return nil
}
