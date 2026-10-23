#!/bin/bash
# 대상 호스트: 에이전트 OFF/ON 반복 비교 (같은 VM, 같은 입력)
#   부하: nginx 정적 페이지 HTTP keep-alive 아님(요청마다 새 연결) + 매 라운드 짧은 프로세스 200개 exec
#   측정: 요청 수/처리량/p50/p95, 에이전트 CPU·RSS, 손실
# 설치: curl 만 사용 (부하 도구 추가 설치 없이 Python 표준 라이브러리로 측정)
set -uo pipefail
ROUNDS=${ROUNDS:-3}
DUR=${DUR:-30}
CONC=${CONC:-8}
PY=$(command -v python3 || echo /usr/libexec/platform-python)
OUT=/var/lib/patchscope/bench
mkdir -p "$OUT"

cat > /tmp/ps-load.py <<'PY'
import sys, time, threading, http.client, subprocess, json
dur, conc = float(sys.argv[1]), int(sys.argv[2])
lat, lock, stop = [], threading.Lock(), time.time() + dur
errors = [0]
def worker():
    mine = []
    while time.time() < stop:
        t = time.perf_counter()
        try:
            c = http.client.HTTPConnection("127.0.0.1", 80, timeout=5)
            c.request("GET", "/")
            c.getresponse().read()
            c.close()
            mine.append(time.perf_counter() - t)
        except Exception:
            errors[0] += 1
    with lock:
        lat.extend(mine)
def execs():
    n = 0
    while time.time() < stop:
        subprocess.run(["/bin/true"]); subprocess.run(["cat", "/etc/os-release"], stdout=subprocess.DEVNULL)
        n += 2
        time.sleep(0.05)
    print(json.dumps({"execs": n}), file=sys.stderr)
ts = [threading.Thread(target=worker) for _ in range(conc)] + [threading.Thread(target=execs)]
[t.start() for t in ts]; [t.join() for t in ts]
lat.sort()
q = lambda p: lat[min(len(lat) - 1, int(len(lat) * p))] * 1000 if lat else 0
print(json.dumps({"requests": len(lat), "rps": round(len(lat) / dur, 1), "p50_ms": round(q(0.5), 3),
                  "p95_ms": round(q(0.95), 3), "p99_ms": round(q(0.99), 3), "errors": errors[0]}))
PY

agent_stats() {
  local pid; pid=$(systemctl show -p MainPID --value patchscope-agent)
  [ "$pid" -gt 0 ] 2>/dev/null || { echo '{}'; return; }
  # utime+stime (ticks), RSS
  awk '{print $14+$15}' /proc/$pid/stat
}

run_round() {
  local mode=$1 r=$2 t0 t1 pid c0 c1 rss
  if [ "$mode" = on ]; then systemctl start patchscope-agent; sleep 15; else systemctl stop patchscope-agent; sleep 3; fi
  pid=$(systemctl show -p MainPID --value patchscope-agent)
  c0=0; [ "$mode" = on ] && c0=$(awk '{print $14+$15}' /proc/$pid/stat)
  t0=$(date +%s.%N)
  res=$($PY /tmp/ps-load.py "$DUR" "$CONC" 2>/tmp/ps-execs.json)
  t1=$(date +%s.%N)
  cpu_pct=0; rss_mib=0
  if [ "$mode" = on ]; then
    c1=$(awk '{print $14+$15}' /proc/$pid/stat)
    cpu_pct=$(awk -v a="$c0" -v b="$c1" -v s="$t0" -v e="$t1" 'BEGIN{printf "%.2f", (b-a)/100/(e-s)*100}')
    rss_mib=$(awk '/VmRSS/{printf "%.1f", $2/1024}' /proc/$pid/status)
  fi
  echo "{\"mode\":\"$mode\",\"round\":$r,\"load\":$res,\"agent_cpu_pct_of_1core\":$cpu_pct,\"agent_rss_mib\":$rss_mib,\"execs\":$(cat /tmp/ps-execs.json)}"
}

WAS=$(systemctl is-active patchscope-agent)
: > "$OUT/results.jsonl"
for r in $(seq 1 "$ROUNDS"); do
  run_round off "$r" | tee -a "$OUT/results.jsonl"
  run_round on "$r"  | tee -a "$OUT/results.jsonl"
done
[ "$WAS" = active ] && systemctl start patchscope-agent || systemctl stop patchscope-agent

$PY - "$OUT/results.jsonl" "$(nproc)" "$(uname -r)" <<'PY'
import json, sys, statistics as st
rows = [json.loads(l) for l in open(sys.argv[1])]
def agg(mode, f):
    return st.median([f(r) for r in rows if r["mode"] == mode])
off_p95, on_p95 = agg("off", lambda r: r["load"]["p95_ms"]), agg("on", lambda r: r["load"]["p95_ms"])
off_rps, on_rps = agg("off", lambda r: r["load"]["rps"]), agg("on", lambda r: r["load"]["rps"])
cpu, rss = agg("on", lambda r: r["agent_cpu_pct_of_1core"]), max(r["agent_rss_mib"] for r in rows if r["mode"] == "on")
print("SUMMARY vcpu=%s kernel=%s rounds=%d" % (sys.argv[2], sys.argv[3], len(rows) // 2))
print("  rps     off=%.1f on=%.1f (%.1f%%)" % (off_rps, on_rps, (on_rps - off_rps) / off_rps * 100))
print("  p95_ms  off=%.3f on=%.3f (%+.1f%%)  target <= +5%%" % (off_p95, on_p95, (on_p95 - off_p95) / off_p95 * 100))
print("  agent   cpu(median, %% of 1 core)=%.2f target <= 5   rss(max)=%.1f MiB target <= 200" % (cpu, rss))
print("  errors  %s" % sum(r["load"]["errors"] for r in rows))
PY
