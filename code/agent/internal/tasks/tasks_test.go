package tasks

import (
	"reflect"
	"testing"
)

func TestValidateRejectsInjection(t *testing.T) {
	bad := []Task{
		{Kind: "shell"},
		{Kind: KindResolvePlan, Packages: []string{"openssl; rm -rf /"}},
		{Kind: KindResolvePlan, Packages: []string{"--setopt=x"}},
		{Kind: KindResolvePlan, Packages: []string{"$(id)"}},
		{Kind: KindResolvePlan, Releasever: "../x"},
	}
	for _, b := range bad {
		if err := b.Validate(); err == nil {
			t.Errorf("expected reject: %+v", b)
		}
	}
	ok := Task{Kind: KindResolvePlan, Packages: []string{"openssl-libs", "glibc", "python3.11-libs", "libstdc++"}, Releasever: "2023.12.20261021"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestArgs(t *testing.T) {
	got := Task{Kind: KindResolvePlan, Packages: []string{"openssl-libs"}, Releasever: "latest"}.Args()
	want := []string{"--releasever", "latest", "-o", "-", "--", "openssl-libs"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
	got = Task{Kind: KindListUpdates}.Args()
	if !reflect.DeepEqual(got, []string{"--list-updates", "-o", "-"}) {
		t.Fatalf("%v", got)
	}
}
