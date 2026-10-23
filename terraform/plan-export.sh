#!/usr/bin/env bash
# 로컬에서: 대상 호스트에서 plan-export 를 실행하고 계획 JSON 을 analysis 로 옮겨 업로드·분석
#   ./plan-export.sh rhel8 openssl-libs glibc          # 지정 패키지 upgrade (종속 거래 포함)
#   RELEASEVER=latest ./plan-export.sh al2023 openssl-libs
#   KERNEL=1 ./plan-export.sh rhel8                     # 커널 plan
# 계획 JSON 은 S3 를 거치지 않고 SSM 출력(base64)으로 전달한다. 비밀 정보는 포함되지 않음.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"
H="${1:?host}"; shift
ARGS=()
[ -n "${RELEASEVER:-}" ] && ARGS+=(--releasever "$RELEASEVER")
[ -n "${KERNEL:-}" ] && ARGS+=(--kernel)
ARGS+=("$@")
LABEL="${LABEL:-$H ${KERNEL:+kernel }${*:-upgrade-all}}"

REPO=https://raw.githubusercontent.com/yeongki0944/ebpf-patch-precheck/$(git rev-parse HEAD)/code/plan-export
TMP=$(mktemp)
cat > "$TMP" <<EOF
set -euo pipefail
install -d -m 0755 /opt/patchscope/plan-export
curl -fsSL -o /opt/patchscope/plan-export/plan_export.py $REPO/plan_export.py
curl -fsSL -o /opt/patchscope/plan-export/patchscope-plan-export $REPO/patchscope-plan-export
chmod 0755 /opt/patchscope/plan-export/patchscope-plan-export
/opt/patchscope/plan-export/patchscope-plan-export $(printf '%q ' "${ARGS[@]}") -o /var/tmp/patchscope-plan.json
echo "PLAN_B64=\$(gzip -c /var/tmp/patchscope-plan.json | base64 -w0)"
EOF
OUT=$(bash ./ssm-run.sh "$H" "$TMP" 600 < /dev/null)
rm -f "$TMP"
B64=$(echo "$OUT" | sed -n 's/^PLAN_B64=//p' | tr -d '\r')
[ -n "$B64" ] || { echo "$OUT"; echo "[ERROR] plan-export 실패" >&2; exit 1; }
echo "$B64" | base64 -d | gunzip | python -c "import sys,json;p=json.load(sys.stdin);print('plan: type=%s items=%d inventory=%s completeness=%s releasever=%s'%(p['plan_type'],len(p['items']),p['inventory_id'],p['completeness'],p['releasever']))"

# analysis 에서 DB 에 직접 등록 (웹 업로드와 같은 검증 로직)
TMP=$(mktemp)
cat > "$TMP" <<EOF
set -euo pipefail
echo '$B64' | base64 -d | gunzip > /tmp/patchscope-plan.json
cd /opt/patchscope/code/server
sudo -u patchscope /opt/patchscope-venv/bin/python -m patchscope_server.cli upload-plan /tmp/patchscope-plan.json $(printf '%q' "$LABEL") < /dev/null
rm -f /tmp/patchscope-plan.json
EOF
bash ./ssm-run.sh analysis "$TMP" 300 < /dev/null
rm -f "$TMP"
