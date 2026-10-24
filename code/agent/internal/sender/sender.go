// Package sender 는 spool 의 항목을 HTTPS 로 서버에 전송한다.
//   - 서버 인증서는 지정 CA 로 검증 (insecure 옵션 없음), TLS 1.2+
//   - Authorization: Bearer <agent token>
//   - 2xx 또는 409(이미 수신, 중복) 이면 spool 에서 삭제
//   - 실패 시 지수 backoff (최대 5분)
package sender

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/yeongki0944/ebpf-patch-precheck/code/agent/internal/model"
	"github.com/yeongki0944/ebpf-patch-precheck/code/agent/internal/spool"
)

type Config struct {
	ServerURL  string // 예: https://ip-10-70-1-10.ap-northeast-2.compute.internal
	CAFile     string
	TokenFile  string
	AgentID    string
	MaxBackoff time.Duration
}

type Sender struct {
	cfg    Config
	sp     *spool.Spool
	client *http.Client
	token  string
	wake   chan struct{}
}

// Client/Token 은 같은 TLS 설정·토큰으로 작업 요청(pull)에 재사용한다.
func (s *Sender) Client() *http.Client { return s.client }
func (s *Sender) Token() string        { return s.token }

func New(cfg Config, sp *spool.Spool) (*Sender, error) {
	if !strings.HasPrefix(cfg.ServerURL, "https://") {
		return nil, fmt.Errorf("server url must be https")
	}
	pem, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificate in %s", cfg.CAFile)
	}
	tok, err := os.ReadFile(cfg.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("read token: %w", err)
	}
	if fi, err := os.Stat(cfg.TokenFile); err == nil && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("token file %s must not be group/world accessible (chmod 600)", cfg.TokenFile)
	}
	if cfg.MaxBackoff == 0 {
		cfg.MaxBackoff = 5 * time.Minute
	}
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConns:        2,
		IdleConnTimeout:     60 * time.Second,
	}
	return &Sender{
		cfg:    cfg,
		sp:     sp,
		client: &http.Client{Transport: tr, Timeout: 60 * time.Second},
		token:  strings.TrimSpace(string(tok)),
		wake:   make(chan struct{}, 1),
	}, nil
}

// Wake 는 새 항목이 spool 에 들어왔음을 알린다.
func (s *Sender) Wake() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

var endpoints = map[string]string{
	"capability": "/api/v1/capability",
	"inventory":  "/api/v1/inventory",
	"history":    "/api/v1/history",
	"batch":      "/api/v1/batches",
}

// Run 은 spool 을 순서대로 비운다. 하나가 실패하면 순서 보존을 위해 뒤 항목도 대기.
func (s *Sender) Run(ctx context.Context) {
	backoff := time.Second
	for {
		err := s.drain(ctx)
		wait := 15 * time.Second
		if err != nil {
			log.Printf("send: %v (retry in %s)", err, backoff)
			wait = backoff
			backoff *= 2
			if backoff > s.cfg.MaxBackoff {
				backoff = s.cfg.MaxBackoff
			}
		} else {
			backoff = time.Second
		}
		select {
		case <-ctx.Done():
			// 종료 시 한 번 더 시도 (짧은 타임아웃)
			c2, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = s.drain(c2)
			cancel()
			return
		case <-s.wake:
		case <-time.After(wait):
		}
	}
}

func (s *Sender) drain(ctx context.Context) error {
	items, err := s.sp.List()
	if err != nil {
		return err
	}
	for _, it := range items {
		ep, ok := endpoints[it.Kind]
		if !ok {
			continue
		}
		body, err := os.ReadFile(it.Path)
		if err != nil {
			continue
		}
		if err := s.post(ctx, ep, body); err != nil {
			return fmt.Errorf("%s: %w", it.Kind, err)
		}
		_ = s.sp.Remove(it.Path)
	}
	return nil
}

type permanentErr struct{ msg string }

func (e permanentErr) Error() string { return e.msg }

func (s *Sender) post(ctx context.Context, ep string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(s.cfg.ServerURL, "/")+ep, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-PatchScope-Schema", model.SchemaVersion)
	req.Header.Set("X-PatchScope-Agent", s.cfg.AgentID)
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	switch {
	case resp.StatusCode/100 == 2, resp.StatusCode == http.StatusConflict:
		return nil
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		// 인증 실패는 조용히 우회하지 않음. 항목은 spool 에 남기고 계속 재시도(토큰 교체 대기)
		return fmt.Errorf("auth rejected (%d): %s", resp.StatusCode, msg)
	default:
		return fmt.Errorf("http %d: %s", resp.StatusCode, msg)
	}
}
