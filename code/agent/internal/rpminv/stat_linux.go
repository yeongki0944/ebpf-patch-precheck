package rpminv

import (
	"golang.org/x/sys/unix"

	"github.com/yeongki0944/ebpf-patch-precheck/code/agent/internal/procfs"
)

// lstatRegular 은 일반 파일만 inode 색인에 넣는다 (심볼릭 링크·디렉터리 제외).
func lstatRegular(p string) (procfs.DevIno, bool) {
	var st unix.Stat_t
	if err := unix.Lstat(p, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return procfs.DevIno{}, false
	}
	return procfs.DevIno{Dev: procfs.DevFromStat(st.Dev), Ino: st.Ino}, true
}
