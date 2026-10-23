package procfs

import (
	"os"
	"testing"
)

func TestDevFromKernel(t *testing.T) {
	if got := DevFromKernel(259<<20 | 1); got != "259:1" {
		t.Fatal(got)
	}
	if got := hexDev("103:01"); got != "259:1" {
		t.Fatal(got)
	}
}

func TestSelfStatAndMaps(t *testing.T) {
	pid := uint32(os.Getpid())
	st, err := ReadStat(pid)
	if err != nil || st.StartTicks == 0 {
		t.Fatalf("stat: %v %+v", err, st)
	}
	maps, err := ReadMaps(pid)
	if err != nil || len(maps) == 0 {
		t.Fatalf("maps: %v %d", err, len(maps))
	}
	exe := ReadExe(pid)
	if !exe.OK {
		t.Fatal("exe")
	}
	// maps 에서 얻은 exe 의 dev/ino 가 stat 결과와 같아야 경로 확정 로직이 성립
	found := false
	for _, m := range maps {
		if m.ID == exe.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("exe %+v not in maps", exe.ID)
	}
}

func TestResolveRequested(t *testing.T) {
	p, ok := ResolveRequested(uint32(os.Getpid()), -100, "x/y")
	wd, _ := os.Getwd()
	if !ok || p != wd+"/x/y" {
		t.Fatal(p)
	}
}
