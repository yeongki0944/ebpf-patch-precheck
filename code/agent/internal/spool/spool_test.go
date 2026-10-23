package spool

import (
	"strings"
	"testing"
)

type batch struct {
	BatchID string   `json:"batch_id"`
	Records []string `json:"records"`
	Pad     string   `json:"pad"`
}

func TestLimitDropsOldestBatchFirst(t *testing.T) {
	s, err := Open(t.TempDir(), 3000)
	if err != nil {
		t.Fatal(err)
	}
	pad := strings.Repeat("x", 800)
	_ = s.Put(1, "inventory", "inv", batch{BatchID: "inv", Pad: pad})
	_ = s.Put(2, "batch", "b1", batch{BatchID: "b1", Records: []string{"a", "b"}, Pad: pad})
	_ = s.Put(3, "batch", "b2", batch{BatchID: "b2", Records: []string{"c"}, Pad: pad})
	_ = s.Put(4, "batch", "b3", batch{BatchID: "b3", Pad: pad})

	items, _ := s.List()
	var kinds []string
	for _, it := range items {
		kinds = append(kinds, it.Kind)
	}
	if len(items) != 3 || kinds[0] != "inventory" {
		t.Fatalf("expected inventory kept and oldest batch dropped, got %v", kinds)
	}
	d := s.TakeDropped()
	if len(d.BatchIDs) != 1 || d.BatchIDs[0] != "b1" || d.Records != 2 {
		t.Fatalf("dropped: %+v", d)
	}
	if s.MaxSeq() != 4 {
		t.Fatalf("maxseq %d", s.MaxSeq())
	}
}
