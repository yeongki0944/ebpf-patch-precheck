package collector

import (
	"github.com/yeongki0944/ebpf-patch-precheck/code/agent/internal/model"
	"github.com/yeongki0944/ebpf-patch-precheck/code/agent/internal/procfs"
	"github.com/yeongki0944/ebpf-patch-precheck/code/agent/internal/rpminv"
)

// resolver 는 이벤트의 (dev,ino) 와 요청 경로로 파일 경로를 확정하고 RPM 소유를 붙인다.
// 원칙: 이벤트 식별자와 일치함을 확인한 경로만 RPM 매핑에 사용한다. 추측 경로는 쓰지 않는다.
type resolver struct {
	inv *rpminv.Inventory
	// 이번 세션에서 검증된 (dev,ino)->경로 색인. 같은 inode 가 교체되면 stat 비교로 무효화.
	idx map[procfs.DevIno]string
}

func newResolver(inv *rpminv.Inventory) *resolver {
	return &resolver{inv: inv, idx: map[procfs.DevIno]string{}}
}

const maxIdx = 200_000

func (r *resolver) remember(id procfs.DevIno, path string) {
	if len(r.idx) >= maxIdx {
		r.idx = map[procfs.DevIno]string{} // 단순 초기화: 이후 재검증으로 다시 채움
	}
	r.idx[id] = path
}

// verify 는 path 를 지금 stat 한 결과가 id 와 같은지 확인한다.
func verify(path string, id procfs.DevIno) bool {
	got, ok := procfs.StatDevIno(path)
	return ok && got == id
}

// byID 는 (dev,ino) 만 있는 경우(mmap, exec 의 실제 exe) 경로를 찾는다.
func (r *resolver) byID(id procfs.DevIno) (string, string) {
	if p, ok := r.idx[id]; ok {
		if verify(p, id) {
			return p, model.PathInodeIndex
		}
		delete(r.idx, id)
	}
	if _, p := r.inv.OwnersByInode(id); p != "" && verify(p, id) {
		r.remember(id, p)
		return p, model.PathInodeIndex
	}
	return "", model.PathUnresolved
}

// fileRef 는 확정된 경로·식별자로 FileRef 를 만든다.
func (r *resolver) fileRef(path, status string, id procfs.DevIno, deleted, otherNS bool) *model.FileRef {
	f := &model.FileRef{Path: path, PathStatus: status, Dev: id.Dev, Ino: id.Ino, Deleted: deleted}
	switch {
	case otherNS:
		// 다른 mount namespace 의 경로는 호스트 RPM DB 로 해석하지 않음
		f.Ownership = model.OwnUnknown
	case deleted:
		// 삭제된 파일: 현재 경로의 새 파일로 해석하지 않고, 인벤토리 로드 시점 inode 가 같았던 경우만 연결
		f.Ownership = model.OwnDeleted
		if pk, _ := r.inv.OwnersByInode(id); len(pk) > 0 {
			f.Packages = pk
		}
	case path == "" || status == model.PathUnresolved || status == model.PathRequested:
		f.Ownership = model.OwnUnknown
	default:
		if pk := r.inv.OwnersByPath(path); len(pk) > 0 {
			f.Ownership, f.Packages = model.OwnRPM, pk
		} else {
			f.Ownership = model.OwnUnmanaged
		}
	}
	return f
}

func (r *resolver) setInventory(inv *rpminv.Inventory) {
	r.inv = inv
}
