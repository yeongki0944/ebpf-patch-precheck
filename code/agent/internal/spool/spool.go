// Package spool 은 전송 대기 데이터를 디스크에 저장한다.
// 용량 한도 초과 시 가장 오래된 미전송 batch 부터 지우고, 지운 batch ID·레코드 수를 기록해
// 다음 batch 에 보고한다 (서버에서 공백 구간으로 표시).
package spool

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type Dropped struct {
	BatchIDs []string
	Records  uint64
}

type Spool struct {
	dir      string
	maxBytes int64
	mu       sync.Mutex
	dropped  Dropped
}

func Open(dir string, maxBytes int64) (*Spool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Spool{dir: dir, maxBytes: maxBytes}, nil
}

// 파일명: <seq 20자리>-<kind>-<id>.json   kind: capability | inventory | batch
// seq 는 에이전트 전체에서 단조 증가하므로 이름순 = 생성순.
func fileName(seq uint64, kind, id string) string {
	return fmt.Sprintf("%020d-%s-%s.json", seq, kind, id)
}

// Put 은 임시 파일에 쓰고 fsync 후 rename 해 원자적으로 저장한다.
func (s *Spool) Put(seq uint64, kind, id string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enforce(int64(len(b)))

	tmp, err := os.CreateTemp(s.dir, ".tmp-*")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(b)
	serr := tmp.Sync()
	cerr := tmp.Close()
	if werr != nil || serr != nil || cerr != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("spool write: %v %v %v", werr, serr, cerr)
	}
	return os.Rename(tmp.Name(), filepath.Join(s.dir, fileName(seq, kind, id)))
}

type Item struct {
	Path string
	Kind string
	Size int64
}

// List 는 생성순으로 정렬된 대기 항목.
func (s *Spool) List() ([]Item, error) {
	ents, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var out []Item
	for _, e := range ents {
		n := e.Name()
		if strings.HasPrefix(n, ".") || !strings.HasSuffix(n, ".json") {
			continue
		}
		parts := strings.SplitN(n, "-", 3)
		if len(parts) != 3 {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, Item{Path: filepath.Join(s.dir, n), Kind: parts[1], Size: fi.Size()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func (s *Spool) Remove(p string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return os.Remove(p)
}

// MaxSeq 는 재시작 시 seq 를 이어가기 위한 현재 최대값.
func (s *Spool) MaxSeq() uint64 {
	items, _ := s.List()
	if len(items) == 0 {
		return 0
	}
	var v uint64
	fmt.Sscanf(filepath.Base(items[len(items)-1].Path), "%020d", &v)
	return v
}

// enforce 는 한도를 넘으면 오래된 batch 부터 지운다. capability/inventory 는 분석 기준이라 마지막에 지운다.
func (s *Spool) enforce(incoming int64) {
	items, err := s.List()
	if err != nil {
		return
	}
	var total int64
	for _, it := range items {
		total += it.Size
	}
	for _, onlyBatch := range []bool{true, false} {
		for _, it := range items {
			if total+incoming <= s.maxBytes {
				return
			}
			if onlyBatch != (it.Kind == "batch") {
				continue
			}
			if it.Kind == "batch" {
				if n, id := countRecords(it.Path); id != "" {
					s.dropped.BatchIDs = append(s.dropped.BatchIDs, id)
					s.dropped.Records += n
				}
			}
			if os.Remove(it.Path) == nil {
				total -= it.Size
			}
		}
	}
}

func countRecords(p string) (uint64, string) {
	b, err := os.ReadFile(p)
	if err != nil {
		return 0, ""
	}
	var v struct {
		BatchID string            `json:"batch_id"`
		Records []json.RawMessage `json:"records"`
	}
	if json.Unmarshal(b, &v) != nil {
		return 0, ""
	}
	return uint64(len(v.Records)), v.BatchID
}

// TakeDropped 는 지금까지 지운 batch 정보를 꺼내고 초기화한다.
func (s *Spool) TakeDropped() Dropped {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.dropped
	s.dropped = Dropped{}
	return d
}
