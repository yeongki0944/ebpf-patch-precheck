#!/usr/bin/env bash
# 서버 업데이트 → 에이전트 배포(이력 전송 포함) → 이력 수신 확인 → 타임라인 페이지 확인
cd "$(dirname "$0")/.."
echo "######## update server"
bash ./ssm-run.sh analysis probes/update-server.sh 300 < /dev/null 2>&1 | tail -2
echo "######## build + deploy agent"
SKIP_SMOKE=1 bash ./pipeline.sh 2>&1 | grep -E 'installed|restarted|rror' | head -10
sleep 60
cat > /tmp/ps-tl.sh <<'EOF'
q() { sudo -u patchscope psql -d patchscope -tA -F ' | ' -c "$1"; }
q "SELECT h.hostname, count(*), max(t.begin_at), count(*) FILTER (WHERE t.username IS NOT NULL) FROM pkg_transactions t JOIN hosts h USING(host_id) GROUP BY 1"
q "SELECT h.hostname, t.tid, t.begin_at, coalesce(t.username,'-'), left(coalesce(t.cmdline,''),70), jsonb_array_length(t.items) FROM pkg_transactions t JOIN hosts h USING(host_id) ORDER BY t.begin_at DESC LIMIT 6"
q "SELECT count(*) FILTER (WHERE install_time IS NOT NULL), count(*) FROM inventory_packages WHERE inventory_id IN (SELECT DISTINCT ON (host_id) inventory_id FROM inventories ORDER BY host_id, received_at DESC)"
T=$(curl -sX PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')
U="https://$(curl -s -H "X-aws-ec2-metadata-token: $T" http://169.254.169.254/latest/meta-data/local-hostname)"
C="curl -sS --cacert /etc/patchscope-server/ca.crt -b /tmp/ps-cj -c /tmp/ps-cj"; rm -f /tmp/ps-cj
code() { $C -o /tmp/ps-page -w '%{http_code}' "$@"; }
code "$U/login" >/dev/null
CSRF=$(grep -o 'name="csrf" value="[^"]*"' /tmp/ps-page | head -1 | sed 's/.*value="//; s/"//')
tr -d '\n' < /root/patchscope-admin-password | code -X POST --data-urlencode 'password@-' --data-urlencode "csrf=$CSRF" "$U/login" >/dev/null
for H in $(q "SELECT host_id FROM hosts ORDER BY hostname"); do
  S=$(q "SELECT session_id FROM sessions WHERE host_id='$H' ORDER BY first_window_start DESC LIMIT 1")
  for p in openssl-libs php8.1-common php-common libxml2; do
    c=$(code "$U/hosts/$H/packages/$p?unit=php-fpm.service&session=$S")
    echo "$(q "SELECT hostname FROM hosts WHERE host_id='$H'") $p: $c events=$(grep -o '<li class="tl ' /tmp/ps-page | wc -l) kinds=$(grep -o 'class="tl k-[a-z]*' /tmp/ps-page | sed 's/.*k-//' | sort | uniq -c | tr '\n' ' ')"
  done
  c=$(code "$U/hosts/$H/services/detail?unit=php-fpm.service&session=$S"); echo "  service page $c links=$(grep -o '/packages/' /tmp/ps-page | wc -l)"
done
journalctl -u patchscope-server --since '-10 min' -p err --no-pager -o cat | grep -E 'Error|line' | tail -6
rm -f /tmp/ps-cj /tmp/ps-page
EOF
echo "######## verify"
bash ./ssm-run.sh analysis /tmp/ps-tl.sh 180 < /dev/null 2>&1 | cut -c1-220
rm -f /tmp/ps-tl.sh
