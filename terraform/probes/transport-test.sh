#!/bin/bash
# 대상 호스트: 전송 장애·인증 오류 시험 (analysis 서버는 건드리지 않음)
#  1) 서버 경로 차단(iptables OUTPUT DROP to analysis:443) 60초 → spool 누적 확인 → 해제 → 재전송·spool 비움
#  2) 같은 batch 재전송 → 409(중복) 확인
#  3) 잘못된 CA 로 실행 → TLS 검증 실패로 전송 거부(우회 없음) 확인
#  4) 잘못된 토큰 → 401, spool 유지 확인
set -uo pipefail
SERVER=$(systemctl show -p ExecStart --value patchscope-agent | grep -o 'https://[^ ;]*' | head -1)
HOST=${SERVER#https://}
IP=$(getent hosts "$HOST" | awk '{print $1}')
SP=/var/lib/patchscope/spool
A=/opt/patchscope/bin/patchscope-agent
echo "server=$SERVER ip=$IP"
spool_n() { ls "$SP"/*.json 2>/dev/null | wc -l; }

echo "=== 1) outage"
systemctl restart patchscope-agent; sleep 20
echo "spool before outage: $(spool_n)"
# analysis 서버 IP 만 blackhole (iptables 없는 AL2023 포함, SSM 경로 영향 없음)
ip route add blackhole "$IP/32"
trap 'ip route del blackhole "$IP/32" 2>/dev/null' EXIT
sleep 90
echo "spool during outage (90s): $(spool_n) (expect >= 8: 10s batch)"
journalctl -u patchscope-agent --since '-100 s' -o cat --no-pager | grep -m2 'send:'
ip route del blackhole "$IP/32"
for i in $(seq 1 60); do sleep 5; n=$(spool_n); [ "$n" -le 1 ] && break; done
echo "spool after recovery: $(spool_n) (waited $((i*5))s)"

echo "=== 2) duplicate resend"
systemctl stop patchscope-agent
# 에이전트가 이미 보낸 batch 를 그대로 다시 보냄
F=$(ls -t /var/lib/patchscope/smoke-spool/*batch*.json 2>/dev/null | head -1)
LAST=$(journalctl -u patchscope-agent -o cat --no-pager | grep -o 'session [0-9a-f]*' | tail -1 | cut -d' ' -f2)
TOK=/etc/patchscope/agent.token
AID=$(hostname -s)
mk_batch() {
  local sid=$1
  cat <<EOF
{"schema_version":"1","agent_id":"$AID","agent_version":"test","batch_id":"$sid-999999","session_id":"$sid","seq":999999,
 "host":{"host_id":"$(cat /etc/machine-id)","boot_id":"$(cat /proc/sys/kernel/random/boot_id)","hostname":"$(hostname)","kernel":"$(uname -r)","os_id":"x","os_version":"x"},
 "inventory_id":"","created_at":"$(date -u +%FT%TZ)","window_start":"$(date -u +%FT%TZ)","reason":"test","complete":true,
 "delta":{},"total":{},"policy":{},"records":[]}
EOF
}
SID=test$(date +%s)
mk_batch "$SID" > /tmp/ps-dup.json
post() { curl -sS -o /dev/null -w '%{http_code}' --cacert /etc/patchscope/ca.crt -H "Authorization: Bearer $(cat $TOK)" \
  -H "X-PatchScope-Agent: $AID" -H 'Content-Type: application/json' --data-binary @/tmp/ps-dup.json "$SERVER/api/v1/batches"; }
echo "first=$(post) second=$(post) (expect 200 409)"

echo "=== 3) wrong CA"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout /tmp/bad.key -out /tmp/bad-ca.crt -subj /CN=bad -days 1 2>/dev/null
mkdir -p /tmp/ps-sp3
timeout 25 $A run --server "$SERVER" --ca /tmp/bad-ca.crt --spool /tmp/ps-sp3 --duration 20s 2>&1 | grep -m2 -E 'send:|x509|certificate'
echo "spool kept with bad CA: $(ls /tmp/ps-sp3/*.json 2>/dev/null | wc -l) (expect >0)"

echo "=== 4) wrong token"
umask 077; echo "0000000000000000000000000000000000000000000000000000000000000000" > /tmp/bad.token
mkdir -p /tmp/ps-sp4
timeout 25 $A run --server "$SERVER" --token /tmp/bad.token --spool /tmp/ps-sp4 --duration 20s 2>&1 | grep -m2 'auth rejected'
echo "spool kept with bad token: $(ls /tmp/ps-sp4/*.json 2>/dev/null | wc -l) (expect >0)"
rm -rf /tmp/ps-sp3 /tmp/ps-sp4 /tmp/bad.key /tmp/bad-ca.crt /tmp/bad.token /tmp/ps-dup.json

systemctl start patchscope-agent
sleep 5; systemctl is-active patchscope-agent
