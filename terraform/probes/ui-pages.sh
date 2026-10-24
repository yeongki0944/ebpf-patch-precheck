#!/bin/bash
# analysis: 로그인 후 서비스 상세(맵)·전후 비교 페이지 렌더링 확인
set -uo pipefail
T=$(curl -sX PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')
U="https://$(curl -s -H "X-aws-ec2-metadata-token: $T" http://169.254.169.254/latest/meta-data/local-hostname)"
C="curl -sS --cacert /etc/patchscope-server/ca.crt -b /tmp/ps-cj -c /tmp/ps-cj"
rm -f /tmp/ps-cj
code() { $C -o /tmp/ps-page -w '%{http_code}' "$@"; }
q() { sudo -u patchscope psql -d patchscope -tA -c "$1"; }
code "$U/login" >/dev/null
CSRF=$(grep -o 'name="csrf" value="[^"]*"' /tmp/ps-page | head -1 | sed 's/.*value="//; s/"//')
echo "login: $(tr -d '\n' < /root/patchscope-admin-password | code -X POST --data-urlencode 'password@-' --data-urlencode "csrf=$CSRF" "$U/login")"
for H in $(q "SELECT host_id FROM hosts ORDER BY hostname"); do
  N=$(q "SELECT hostname FROM hosts WHERE host_id='$H'")
  S=$(q "SELECT session_id FROM sessions WHERE host_id='$H' ORDER BY first_window_start DESC LIMIT 1")
  for unit in php-fpm.service nginx.service postgresql.service; do
    c=$(code "$U/hosts/$H/services/detail?unit=$unit&session=$S")
    echo "$N $unit: $c bytes=$(wc -c < /tmp/ps-page) svg=$(grep -c '<svg' /tmp/ps-page) nodes=$(grep -o '<circle' /tmp/ps-page | wc -l) upd=$(grep -o 'b-purple' /tmp/ps-page | wc -l)"
  done
  c=$(code "$U/hosts/$H/compare")
  echo "$N compare: $c bytes=$(wc -c < /tmp/ps-page) cards=$(grep -o 'class="card svc-chg"' /tmp/ps-page | wc -l) up=$(grep -o '<li class="up">' /tmp/ps-page | wc -l) add=$(grep -o '<li class="add">' /tmp/ps-page | wc -l) rm=$(grep -o '<li class="rm">' /tmp/ps-page | wc -l)"
  grep -o 'class="svc-name">[^<]*' /tmp/ps-page | sed 's/.*>//' | head -8 | paste -sd' '
  grep -o '임시 unit [0-9]*개' /tmp/ps-page
done
journalctl -u patchscope-server --since '-5 min' -p err --no-pager -o cat | grep -E 'Error|line' | tail -6
rm -f /tmp/ps-cj /tmp/ps-page
