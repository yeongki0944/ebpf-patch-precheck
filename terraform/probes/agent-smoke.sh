#!/bin/bash
# 대상 호스트 스모크 시험: precheck → 30초 수집(spool only) 중 정답을 아는 작업 실행 → 결과 검증
set -uo pipefail
A=/opt/patchscope/bin/patchscope-agent
SP=/var/lib/patchscope/smoke-spool
rm -rf "$SP"
echo "=== precheck"
$A precheck --spool "$SP" | grep -vE '^\s+\[OK' ; echo "rc=$?"

echo "=== run 25s"
$A run --spool "$SP" --duration 25s --batch 5s > /tmp/agent-smoke.log 2>&1 &
APID=$!
sleep 8   # 로드 + 인벤토리 + 초기 스냅샷

# 정답 작업: 짧은 프로세스 (주기 스캔 사이에 끝남), 성공/실패 open, 라이브러리 로딩
/usr/bin/curl --version > /dev/null
cat /etc/os-release > /dev/null
cat /etc/patchscope-no-such-file 2>/dev/null
openssl version > /dev/null 2>&1
(cd /etc && read -r _ < ./hostname; sleep 2)      # 상대 경로 (cwd 를 읽을 수 있게 프로세스 유지)
(cd /etc && cat ./hostname > /dev/null)          # 단기 프로세스 상대 경로: 확정 못 하면 unresolved 여야 함
cp /usr/bin/true /tmp/ps-deleted-true && /tmp/ps-deleted-true && rm -f /tmp/ps-deleted-true  # RPM 미소유
sleep 1; for i in 1 2 3; do /bin/true; done      # PID 새 인스턴스 3개
wait $APID
echo "agent exit=$?"
tail -6 /tmp/agent-smoke.log

echo "=== verify"
PY=$(command -v python3 || echo /usr/libexec/platform-python)
$PY - "$SP" <<'PY'
import json, glob, sys, collections
recs, batches, caps, invs = [], [], [], []
for f in sorted(glob.glob(sys.argv[1] + "/*.json")):
    d = json.load(open(f))
    kind = f.split("/")[-1].split("-")[1]
    if kind == "batch": batches.append(d); recs += d["records"]
    elif kind == "capability": caps.append(d)
    elif kind == "inventory": invs.append(d)
print("batches=%d records=%d caps=%s inv_pkgs=%s" % (len(batches), len(recs),
      [c["report"]["status"] for c in caps], [len(i["inventory"]["packages"]) for i in invs]))
t = batches[-1]["total"] if batches else {}
print("totals:", {k: v for k, v in t.items() if v})
print("complete batches: %d/%d" % (sum(b["complete"] for b in batches), len(batches)))
print("kinds:", dict(collections.Counter(r["kind"] for r in recs)))

def find(kind, pred):
    return [r for r in recs if r["kind"] == kind and pred(r)]
def path(r): return (r.get("file") or {}).get("path", "")
def req(r): return (r.get("file") or {}).get("requested_path", "")
checks = []
def check(name, ok, detail=""):
    checks.append(ok); print(("PASS " if ok else "FAIL ") + name, detail)

ex = find("exec", lambda r: path(r).endswith("/curl"))
check("exec curl with rpm owner", any(r["file"]["ownership"] == "rpm" for r in ex),
      [(r["file"]["path"], r["file"].get("packages")) for r in ex[:1]])
op = find("file_open", lambda r: path(r) == "/etc/os-release" or path(r).endswith("/os-release"))
check("open /etc/os-release ok + owner", any(r["ok"] and r["file"]["ownership"] == "rpm" for r in op),
      [(r["file"]["path"], r["file"].get("packages")) for r in op[:1]])
fail = find("file_open", lambda r: req(r) == "/etc/patchscope-no-such-file")
check("failed open recorded separately", any(not r["ok"] and r["errno"] == 2 and r["file"]["path_status"] == "requested_only" for r in fail))
rel = find("file_open", lambda r: req(r) == "./hostname")
check("relative path resolved (live process)", any(path(r) == "/etc/hostname" and r["file"]["path_status"] == "verified" for r in rel),
      [(r["comm"], path(r), r["file"]["path_status"]) for r in rel])
check("relative path never guessed", all(path(r) in ("", "/etc/hostname") for r in rel))
import re
libc = [r for r in recs if r["kind"] in ("file_mmap", "file_open", "mapped_file")
        and re.search(r"/libc(\.so|-[0-9.]+\.so)", path(r))  # AL2023: libc.so.6, RHEL8: libc-2.28.so
        and r.get("comm") in ("curl", "cat", "openssl")]
check("libc mapped/opened by short process, rpm owner", any(r["file"]["ownership"] == "rpm" for r in libc),
      sorted({(path(r), tuple(r["file"].get("packages") or [])) for r in libc})[:1])
# 경로가 있는 시스템 라이브러리가 rpm 이 아닌 것으로 분류되면 원인 표시
bad = [r for r in recs if path(r).startswith("/usr/lib64/") and (r.get("file") or {}).get("ownership") != "rpm"
       and not (r.get("file") or {}).get("deleted")]
check("/usr/lib64 files with path are rpm-owned", not bad,
      collections.Counter((r["file"]["ownership"], r["file"]["path_status"], r["file"].get("note", ""), r.get("comm")) for r in bad).most_common(5))
ssl = [r for r in recs if r.get("comm") in ("curl", "openssl") and ("libssl" in path(r) or "libcrypto" in path(r))]
check("openssl libs linked to process", any(r["file"]["ownership"] == "rpm" for r in ssl),
      sorted({(path(r), tuple(r["file"].get("packages") or [])) for r in ssl})[:2])
um = find("exec", lambda r: req(r) == "/tmp/ps-deleted-true" or path(r) == "/tmp/ps-deleted-true")
check("unmanaged binary not treated as rpm", any(r["file"]["ownership"] in ("unmanaged", "deleted", "unknown") for r in um),
      [(r["file"].get("path"), r["file"]["ownership"], r["file"]["path_status"]) for r in um[:1]])
tr = find("exec", lambda r: path(r).endswith("/true") and r.get("comm") == "true")
check("pid instances distinct (true x3)", len({r["proc"]["key"] for r in tr}) >= 3, len({r["proc"]["key"] for r in tr}))
ext = find("exit", lambda r: r.get("comm") == "cat")
check("exit events", len(ext) >= 1)
snap = find("process", lambda r: r.get("unit") == "sshd.service" or r.get("unit") == "amazon-ssm-agent.service")
check("snapshot unit attribution (cgroup)", len(snap) >= 1, [(r["comm"], r["unit"]) for r in snap[:2]])
agent_self = [r for r in recs if r.get("comm") in ("patchscope-agen", "rpm") and r["source"] == "ebpf"]
check("agent self/rpm child excluded", len(agent_self) == 0, len(agent_self))
lossy = [b["batch_id"] for b in batches if not b["complete"]]
check("no event loss (or loss flagged incomplete)", all((b["delta"]["perf_lost"] + b["delta"]["kernel_output_fail"] == 0) == b["complete"] for b in batches),
      {"incomplete_batches": lossy})
check("no event loss in smoke workload", not lossy, t.get("perf_lost", 0))
own = collections.Counter((r.get("file") or {}).get("ownership") for r in recs if r.get("file"))
print("ownership:", dict(own))
print("path_status:", dict(collections.Counter((r.get("file") or {}).get("path_status") for r in recs if r.get("file"))))
print("RESULT %d/%d" % (sum(checks), len(checks)))
PY
