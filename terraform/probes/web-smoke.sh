#!/bin/bash
# analysis: 웹 화면 렌더링 확인 (로그인 → 각 페이지 GET). 비밀번호는 출력하지 않음.
set -uo pipefail
T=$(curl -sX PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')
PDNS=$(curl -s -H "X-aws-ec2-metadata-token: $T" http://169.254.169.254/latest/meta-data/local-hostname)
U="https://$PDNS"
C="curl -sS --cacert /etc/patchscope-server/ca.crt -b /tmp/ps-cj -c /tmp/ps-cj"
rm -f /tmp/ps-cj
code() { $C -o /tmp/ps-page -w '%{http_code}' "$@"; }

echo "unauth / -> $(code "$U/") (expect 303)"
echo "bad token -> $(curl -sS --cacert /etc/patchscope-server/ca.crt -o /dev/null -w '%{http_code}' -X POST -H 'Authorization: Bearer 0000000000000000000000' -H 'Content-Type: application/json' -d '{}' "$U/api/v1/batches") (expect 401)"
echo "no CA verify -> $(curl -sS -o /dev/null -w '%{http_code}' "$U/api/v1/health" 2>&1 | tail -c 80) (expect TLS error)"

code "$U/login" >/dev/null
CSRF=$(grep -o 'name="csrf" value="[^"]*"' /tmp/ps-page | head -1 | sed 's/.*value="//; s/"//')
echo "login wrong pw -> $(code -X POST --data-urlencode 'password=wrong-password-xx' --data-urlencode "csrf=$CSRF" "$U/login") $(grep -c 'invalid password' /tmp/ps-page)"
# 파일의 개행을 제거해 stdin 으로 전달 (명령행·로그에 비밀번호를 남기지 않음)
echo "login -> $(tr -d '\n' < /root/patchscope-admin-password | code -X POST --data-urlencode "password@-" --data-urlencode "csrf=$CSRF" "$U/login") (expect 303)"

check() {
  local name=$1 url=$2 c
  c=$(code "$url")
  printf '%-22s %s bytes=%s %s\n' "$name" "$c" "$(wc -c < /tmp/ps-page)" "$(grep -o '<h1>[^<]*' /tmp/ps-page | head -1 | sed 's/<h1>//')"
  [ "$c" = 200 ] || head -c 400 /tmp/ps-page
}
check hosts "$U/"
q() { sudo -u patchscope psql -d patchscope -tA -c "$1"; }
for H in $(q "SELECT host_id FROM hosts ORDER BY hostname"); do
  check "host" "$U/hosts/$H"
  S=$(q "SELECT session_id FROM sessions WHERE host_id='$H' ORDER BY last_created_at DESC LIMIT 1")
  [ -n "$S" ] && check "session" "$U/sessions/$S"
  [ -n "$S" ] && check "service nginx" "$U/sessions/$S/service?unit=nginx.service"
done
for P in $(q "SELECT id FROM patch_plans ORDER BY id"); do
  check "plan $P" "$U/plans/$P"
  check "plan $P json" "$U/plans/$P/report.json"
  check "plan $P csv" "$U/plans/$P/report.csv"; head -3 /tmp/ps-page | cut -c1-200
done
S2=$(q "SELECT string_agg(session_id, ' ') FROM (SELECT session_id FROM sessions ORDER BY last_created_at DESC LIMIT 2) s")
set -- $S2
[ $# -eq 2 ] && check compare "$U/compare?before=$1&after=$2"
check tz-utc "$U/tz/UTC"
journalctl -u patchscope-server --since '-5 min' -p err --no-pager -o cat | tail -20
rm -f /tmp/ps-cj /tmp/ps-page
