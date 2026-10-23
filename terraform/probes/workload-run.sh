#!/bin/bash
# 대상 호스트: 패치 전후 동일 작업 수행 + 기능 확인 결과 출력
#   1) 서비스 재시작(새 라이브러리 로드)  2) HTTP/Redis/배치/CLI 기능 확인 3회  3) 짧은 부하
set -uo pipefail
. /etc/os-release
REDIS=redis; [ "$ID" = amzn ] && REDIS=redis6
RCLI=redis-cli; command -v redis6-cli >/dev/null && RCLI=redis6-cli
PY=$(command -v python3 || echo /usr/libexec/platform-python)
systemctl restart nginx "$REDIS"
sleep 3
ok=0; fail=0
for i in 1 2 3; do
  curl -fsS -o /dev/null http://127.0.0.1/ && ok=$((ok+1)) || fail=$((fail+1))
  [ "$($RCLI ping 2>/dev/null)" = PONG ] && ok=$((ok+1)) || fail=$((fail+1))
  systemctl start ps-batch.service && ok=$((ok+1)) || fail=$((fail+1))
  systemctl start ps-cli.service && ok=$((ok+1)) || fail=$((fail+1))
  sleep 2
done
echo "functional ok=$ok fail=$fail"
echo "batch: $(/usr/local/bin/ps-batch.py 2>&1)"
echo "openssl: $(openssl version)"
echo "services: $(systemctl is-active nginx $REDIS ps-batch.timer ps-cli.timer patchscope-agent | paste -sd' ')"
echo "kernel errors since boot: $(journalctl -k -p err -b --no-pager -q | wc -l)"
echo "nginx maps libssl: $(grep -ho '/[^ ]*libssl[^ ]*' /proc/$(systemctl show -p MainPID --value nginx)/maps | sort -u | paste -sd,)"
