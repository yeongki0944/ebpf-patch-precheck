#!/bin/bash
# 대상 호스트: 패치 전후 동일 작업 (서비스 재시작 없음 — 재시작은 패치 단계에서 운영자가 결정)
set -uo pipefail
. /etc/os-release
REDIS=redis; [ "$ID" = amzn ] && REDIS=redis6
RCLI=redis-cli; command -v redis6-cli >/dev/null && RCLI=redis6-cli
ok=0; fail=0
for i in 1 2 3; do
  for p in index image xml db fetch; do curl -fsS -o /dev/null "http://127.0.0.1/app/$p.php" && ok=$((ok+1)) || fail=$((fail+1)); done
  curl -fsS -o /dev/null http://127.0.0.1/ && ok=$((ok+1)) || fail=$((fail+1))
  [ "$($RCLI ping 2>/dev/null)" = PONG ] && ok=$((ok+1)) || fail=$((fail+1))
  systemctl start ps-batch.service ps-cli.service ps-web.service && ok=$((ok+1)) || fail=$((fail+1))
  sudo -u apache /usr/local/bin/ps-report.py >/dev/null 2>&1 && ok=$((ok+1)) || fail=$((fail+1))
  sleep 3
done
echo "functional ok=$ok fail=$fail"
echo "openssl: $(openssl version) | report: $(sudo -u apache /usr/local/bin/ps-report.py 2>&1 | cut -c1-80)"
echo "services: $(systemctl is-active nginx php-fpm postgresql $REDIS patchscope-agent | paste -sd' ')"
echo "kernel=$(uname -r) boot=$(cut -c1-8 /proc/sys/kernel/random/boot_id) kernel_err=$(journalctl -k -p err -b --no-pager -q | wc -l)"
