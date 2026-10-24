#!/bin/bash
# analysis: CloudFront 경유 로그인·페이지 확인 (비밀번호는 출력하지 않음). CF_URL 을 첫 줄 export 로 주입
set -uo pipefail
C="curl -sS -b /tmp/cf-cj -c /tmp/cf-cj"; rm -f /tmp/cf-cj
code() { $C -o /tmp/cf-page -w '%{http_code}' "$@"; }
code "$CF_URL/login" >/dev/null
CSRF=$(grep -o 'name="csrf" value="[^"]*"' /tmp/cf-page | head -1 | sed 's/.*value="//; s/"//')
echo "login: $(tr -d '\n' < /root/patchscope-admin-password | code -X POST --data-urlencode 'password@-' --data-urlencode "csrf=$CSRF" "$CF_URL/login")"
q() { sudo -u patchscope psql -d patchscope -tA -c "$1"; }
H=$(q "SELECT host_id FROM hosts WHERE hostname='patchscope-al2023'")
for p in "/" "/static/app.css" "/hosts/$H" "/hosts/$H/changes" "/hosts/$H/services" "/hosts/$H/compare"; do
  echo "$p -> $(code "$CF_URL$p") $(wc -c < /tmp/cf-page)B"
done
T=$(q "SELECT max(tid) FROM pkg_transactions WHERE host_id='$H'")
echo "/changes/$T -> $(code "$CF_URL/hosts/$H/changes/$T") $(wc -c < /tmp/cf-page)B restart=$(grep -o '재시작 필요' /tmp/cf-page | wc -l)"
echo "headers: $($C -sI "$CF_URL/" | grep -iE '^x-cache|^cache-control' | tr -d '\r' | paste -sd' ')"
rm -f /tmp/cf-cj /tmp/cf-page
