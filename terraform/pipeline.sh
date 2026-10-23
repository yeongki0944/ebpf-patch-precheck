#!/usr/bin/env bash
# 로컬에서: (git push 후) analysis 빌드·테스트·업로드 → 대상 배포 → 스모크 시험
#   ./pipeline.sh                 # al2023 rhel8 모두
#   ./pipeline.sh rhel8           # 특정 대상만
#   SKIP_SMOKE=1 ./pipeline.sh
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"
TARGETS=("$@"); [ ${#TARGETS[@]} -eq 0 ] && TARGETS=(al2023 rhel8)
BUCKET=$(terraform output -raw artifacts_bucket | tr -d '\r')
REV=$(git rev-parse --short HEAD)
git fetch -q origin main
[ "$(git rev-parse origin/main)" = "$(git rev-parse HEAD)" ] || { echo "[ERROR] HEAD 가 origin/main 과 다릅니다. push 하세요." >&2; exit 1; }

TMP=$(mktemp)
{ echo "export BUCKET=$BUCKET"; cat probes/build-agent.sh; } > "$TMP"
echo "######## build $REV on analysis"
bash ./ssm-run.sh analysis "$TMP" 900 < /dev/null 2>&1 | grep -vE '^\s+\[OK' | tail -30
rm -f "$TMP"

bash ./deploy-agent.sh "$REV" "${TARGETS[@]}" || exit 1
[ -n "${SKIP_SMOKE:-}" ] && exit 0
for h in "${TARGETS[@]}"; do
  echo "######## smoke $h"
  bash ./ssm-run.sh "$h" probes/agent-smoke.sh 300 < /dev/null 2>&1 | sed -n '/=== verify/,$p'
done
