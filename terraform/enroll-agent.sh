#!/usr/bin/env bash
# 로컬에서 실행: 대상 호스트에 CA·토큰·systemd 서비스를 설치하고 서버에 토큰 해시를 등록한다.
#   ./enroll-agent.sh al2023 rhel8           # 신규/재등록 (토큰이 있으면 유지)
#   ROTATE=1 ./enroll-agent.sh rhel8         # 토큰 교체
#
# 비밀 처리:
#   - 토큰은 대상 호스트에서 생성 → /etc/patchscope/agent.token (0600). 원문은 호스트 밖으로 나가지 않음
#   - 서버에는 sha256 만 등록 (patchscope-admin register-agent)
#   - CA 는 공개 인증서만 전달 (개인키는 analysis 에만)
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"
run() { bash ./ssm-run.sh "$@" < /dev/null; }

SERVER_DNS=$(terraform output -raw analysis_private_dns | tr -d '\r')
CA_PEM=$(echo 'cat /etc/patchscope-server/ca.crt' > /tmp/ps-ca.sh; run analysis /tmp/ps-ca.sh 60 2>/dev/null; rm -f /tmp/ps-ca.sh)
echo "$CA_PEM" | grep -q "BEGIN CERTIFICATE" || { echo "[ERROR] CA 를 가져오지 못함. setup-server 실행 여부 확인" >&2; exit 1; }
CA_B64=$(printf '%s\n' "$CA_PEM" | base64 -w0)

for h in "$@"; do
  echo "=== enroll $h"
  TMP=$(mktemp)
  cat > "$TMP" <<EOF
set -euo pipefail
install -d -m 0700 /etc/patchscope /var/lib/patchscope/spool
echo '$CA_B64' | base64 -d > /etc/patchscope/ca.crt
chmod 0644 /etc/patchscope/ca.crt
if [ ! -s /etc/patchscope/agent.token ] || [ "${ROTATE:-}" = 1 ]; then
  umask 077
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > /etc/patchscope/agent.token
fi
chmod 0600 /etc/patchscope/agent.token
AGENT_ID=\$(hostname -s)
cat > /etc/systemd/system/patchscope-agent.service <<UNIT
[Unit]
Description=PatchScope collection agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/opt/patchscope/bin/patchscope-agent run --server https://$SERVER_DNS --agent-id \$AGENT_ID
Restart=on-failure
RestartSec=10
# 수집에 root·BPF 권한 필요. 자원 상한
MemoryMax=400M
CPUQuota=50%
Nice=5

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
echo "agent_id=\$AGENT_ID"
echo "token_sha256=\$(tr -d '\n' < /etc/patchscope/agent.token | sha256sum | cut -d' ' -f1)"
EOF
  OUT=$(run "$h" "$TMP" 120)
  rm -f "$TMP"
  AGENT_ID=$(echo "$OUT" | sed -n 's/^agent_id=//p' | tr -d '\r')
  TH=$(echo "$OUT" | sed -n 's/^token_sha256=//p' | tr -d '\r')
  [[ "$TH" =~ ^[0-9a-f]{64}$ ]] || { echo "$OUT"; echo "[ERROR] token hash 실패" >&2; exit 1; }
  echo "patchscope-admin register-agent '$AGENT_ID' '$TH'" > /tmp/ps-reg.sh
  run analysis /tmp/ps-reg.sh 60
  rm -f /tmp/ps-reg.sh
  echo 'systemctl enable patchscope-agent >/dev/null 2>&1; systemctl restart patchscope-agent; sleep 15; systemctl is-active patchscope-agent; journalctl -u patchscope-agent -n 8 --no-pager -o cat' > /tmp/ps-start.sh
  run "$h" /tmp/ps-start.sh 120
  rm -f /tmp/ps-start.sh
done
