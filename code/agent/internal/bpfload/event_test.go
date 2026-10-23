package bpfload

import (
	"encoding/binary"
	"testing"
)

func TestDecodeOffsets(t *testing.T) {
	b := make([]byte, EventSize)
	le := binary.LittleEndian
	le.PutUint64(b[0:], 11)
	le.PutUint64(b[8:], 22)
	le.PutUint64(b[16:], 33)
	le.PutUint64(b[24:], 44)
	le.PutUint64(b[32:], uint64(0xFFFFFFFFFFFFFFFE)) // -2
	le.PutUint32(b[40:], EvOpen)
	le.PutUint32(b[44:], 101)
	le.PutUint32(b[48:], 100)
	le.PutUint32(b[52:], 1)
	le.PutUint32(b[56:], 1000)
	le.PutUint32(b[60:], 259<<20|3)
	le.PutUint32(b[64:], 0o2000000)
	le.PutUint32(b[68:], 5)
	le.PutUint32(b[72:], uint32(0xFFFFFF9C)) // -100
	le.PutUint32(b[76:], 1)
	le.PutUint32(b[80:], KFKPathComplete)
	k := []byte("passwd\x00etc\x00/\x00")
	le.PutUint32(b[84:], uint32(len(k)))
	copy(b[88:], "bash")
	copy(b[104:], "nginx.service")
	copy(b[168:], "redis.service")
	copy(b[232:], "passwd")
	copy(b[488:], k)

	var e Event
	if err := Decode(b, &e); err != nil {
		t.Fatal(err)
	}
	if e.TsNs != 11 || e.StartBootNs != 22 || e.ParentStartNs != 33 || e.Ino != 44 || e.Ret != -2 {
		t.Fatalf("u64 fields: %+v", e)
	}
	if e.Type != EvOpen || e.PID != 101 || e.TGID != 100 || e.PPID != 1 || e.UID != 1000 || e.Dev != 259<<20|3 {
		t.Fatalf("u32 fields: %+v", e)
	}
	if e.DFD != -100 || !e.HasIdent || e.Comm != "bash" || e.Path != "passwd" {
		t.Fatalf("tail fields: %+v", e)
	}
	if e.CgroupDfl != "nginx.service" || e.CgroupPids != "redis.service" || e.KPath != "/etc/passwd" {
		t.Fatalf("cgroup/kpath: %+v", e)
	}
	le.PutUint32(b[80:], KFKPathComplete|KFKPathTruncated)
	_ = Decode(b, &e)
	if e.KPath != "" {
		t.Fatal("truncated kpath must not be used")
	}
	if err := Decode(b[:EventSize-1], &e); err == nil {
		t.Fatal("short buffer must fail")
	}
}

func TestAssembleKPath(t *testing.T) {
	cases := map[string]string{
		"libc.so.6\x00lib64\x00usr\x00/\x00": "/usr/lib64/libc.so.6",
		"/\x00":                              "/",
		"a\x00":                              "/a",
	}
	for in, want := range cases {
		if got := AssembleKPath([]byte(in)); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}
