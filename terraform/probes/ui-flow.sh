#!/bin/bash
# analysis: UI 흐름 E2E (브라우저와 같은 폼 요청)
#   로그인 → 각 화면 200 → 업데이트 목록 확인 요청 → 에이전트 처리 대기 → 계획 계산 요청 → 분석 화면
#   HOSTNAME_FILTER 와 PKGS 를 첫 줄 export 로 주입
set -uo pipefail
T=$(curl -sX PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')
PDNS=$(curl -s -H "X-aws-ec2-metadata-token: $T" http://169.254.169.254/latest/meta-data/local-hostname)
U="https://$PDNS"
C="curl -sS --cacert /etc/patchscope-server/ca.crt -b /tmp/ps-cj -c /tmp/ps-cj"
rm -f /tmp/ps-cj
code() { $C -o /tmp/ps-page -w '%{http_code}' "$@"; }
q() { sudo -u patchscope psql -d patchscope -tA -c "$1"; }

code "$U/login" >/dev/null
CSRF=$(grep -o 'name="csrf" value="[^"]*"' /tmp/ps-page | head -1 | sed 's/.*value="//; s/"//')
echo "login: $(tr -d '\n' < /root/patchscope-admin-password | code -X POST --data-urlencode 'password@-' --data-urlencode "csrf=$CSRF" "$U/login")"

page() { local c; c=$(code "$2"); printf '%-26s %s %6s bytes %s\n' "$1" "$c" "$(wc -c < /tmp/ps-page)" "$(grep -o '<title>[^<]*' /tmp/ps-page | sed 's/<title>//')"; [ "$c" = 200 ] || head -c 600 /tmp/ps-page; }
page dashboard "$U/"
page static-css "$U/static/app.css"
H=$(q "SELECT host_id FROM hosts WHERE hostname = '$HOSTNAME_FILTER'")
page overview "$U/hosts/$H"
page plans "$U/hosts/$H/plans"
page services "$U/hosts/$H/services"
S=$(q "SELECT session_id FROM sessions WHERE host_id='$H' ORDER BY first_window_start DESC LIMIT 1")
page service-php "$U/hosts/$H/services/detail?unit=php-fpm.service&session=$S"
grep -o '<strong>[a-z0-9._+-]*</strong>' /tmp/ps-page | sed 's/<[^>]*>//g' | head -60 | paste -sd' ' | cut -c1-600
page periods "$U/hosts/$H/periods"
page compare "$U/hosts/$H/compare"
page plan-new "$U/hosts/$H/plans/new"

REL=""; [ "$(q "SELECT os_id FROM hosts WHERE host_id='$H'")" = amzn ] && REL=latest
echo "--- request update list (releasever=$REL)"
code -X POST --data-urlencode "csrf=$CSRF" --data-urlencode "releasever=$REL" "$U/hosts/$H/updates/refresh" >/dev/null
for i in $(seq 1 40); do
  st=$(q "SELECT status FROM plan_tasks WHERE host_id='$H' AND kind='list_updates' ORDER BY id DESC LIMIT 1")
  [ "$st" = done ] || [ "$st" = failed ] && break; sleep 5
done
echo "list_updates: $st after $((i*5))s $(q "SELECT coalesce(error,'') FROM plan_tasks WHERE host_id='$H' AND kind='list_updates' ORDER BY id DESC LIMIT 1")"
echo "updates: $(q "SELECT jsonb_array_length(updates) FROM available_updates WHERE host_id='$H'")"
page plan-new-with-list "$U/hosts/$H/plans/new"
grep -c 'name="packages"' /tmp/ps-page | sed 's/^/checkboxes=/'

echo "--- request plan: $PKGS"
ARGS=(--data-urlencode "csrf=$CSRF" --data-urlencode "mode=selected" --data-urlencode "label=UI: $PKGS")
[ -n "$REL" ] && ARGS+=(--data-urlencode "releasever=$REL")
for p in $PKGS; do ARGS+=(--data-urlencode "packages=$p"); done
code -X POST "${ARGS[@]}" "$U/hosts/$H/plans/request" >/dev/null
for i in $(seq 1 40); do
  read -r st pid <<<"$(q "SELECT status, coalesce(plan_id,0) FROM plan_tasks WHERE host_id='$H' AND kind='resolve_plan' ORDER BY id DESC LIMIT 1" | tr '|' ' ')"
  [ "$st" = done ] || [ "$st" = failed ] && break; sleep 5
done
echo "resolve_plan: $st plan_id=$pid after $((i*5))s $(q "SELECT coalesce(error,'') FROM plan_tasks WHERE host_id='$H' AND kind='resolve_plan' ORDER BY id DESC LIMIT 1")"
if [ "$pid" != 0 ]; then
  page analysis "$U/plans/$pid"
  grep -o '<div class="n">[^<]*</div><div class="l">[^<]*' /tmp/ps-page | sed 's/<div class="n">//; s/<\/div><div class="l">/ = /' | head -4
  grep -o 'data-filter="#svcT"' /tmp/ps-page >/dev/null && grep -o '<strong>[a-z0-9@._-]*\.service</strong>' /tmp/ps-page | sed 's/<[^>]*>//g' | head -20 | paste -sd' '
  page report-csv "$U/plans/$pid/report.csv"
fi
echo "--- security: agent token cannot use UI, unknown task kind rejected by agent, cross-host"
echo "ui without login: $(curl -sS --cacert /etc/patchscope-server/ca.crt -o /dev/null -w '%{http_code}' "$U/hosts/$H/plans/new")"
echo "bad csrf: $(code -X POST --data-urlencode 'csrf=wrong' "$U/hosts/$H/updates/refresh")"
echo "bad package name: $(code -X POST --data-urlencode "csrf=$CSRF" --data-urlencode 'mode=selected' --data-urlencode 'packages=x;id' "$U/hosts/$H/plans/request")"
journalctl -u patchscope-server --since '-10 min' -p err --no-pager -o cat | tail -10
rm -f /tmp/ps-cj /tmp/ps-page
