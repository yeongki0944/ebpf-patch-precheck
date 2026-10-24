#!/usr/bin/env bash
# 로컬에서 실행: analysis 가 S3 에 올린 에이전트를 대상 호스트에 설치 (presigned URL, sha256 검증)
#   ./deploy-agent.sh <rev> al2023 rhel8
# 대상 role 에는 S3 권한이 없으므로 로컬 SSO 자격증명으로 10분짜리 URL 을 발급한다.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE="${PROFILE:-$(grep -E '^\s*aws_profile' "$DIR/terraform.tfvars" | sed -E 's/.*"(.*)".*/\1/' | tr -d '\r')}"
REGION="${REGION:-ap-northeast-2}"
for v in AWS_REGION AWS_DEFAULT_REGION; do [ -z "${!v:-}" ] && unset "$v"; done

REV="${1:?rev (git short sha)}"; shift
BUCKET=$(cd "$DIR" && terraform output -raw artifacts_bucket | tr -d '\r')
KEY="agent/$REV/patchscope-agent"
SHA=$(aws s3 cp --profile "$PROFILE" --region "$REGION" "s3://$BUCKET/$KEY.sha256" - | awk '{print $1}')
[[ "$SHA" =~ ^[0-9a-f]{64}$ ]] || { echo "[ERROR] sha256 없음: s3://$BUCKET/$KEY.sha256" >&2; exit 1; }
URL=$(aws s3 presign --profile "$PROFILE" --region "$REGION" --expires-in 600 "s3://$BUCKET/$KEY" | tr -d '\r')
PE_PY=$(git -C "$DIR" show "$REV:code/plan-export/plan_export.py" | base64 -w0)
PE_SH=$(git -C "$DIR" show "$REV:code/plan-export/patchscope-plan-export" | base64 -w0)

TMP=$(mktemp)
cat > "$TMP" <<EOF
set -euo pipefail
install -d -m 0755 /opt/patchscope/bin /opt/patchscope/plan-export
install -d -m 0700 /etc/patchscope /var/lib/patchscope/spool
curl -fsSL -o /opt/patchscope/bin/patchscope-agent.new '$URL'
echo "$SHA  /opt/patchscope/bin/patchscope-agent.new" | sha256sum -c -
chmod 0755 /opt/patchscope/bin/patchscope-agent.new
mv -f /opt/patchscope/bin/patchscope-agent.new /opt/patchscope/bin/patchscope-agent
# plan-export (계산 전용 도구, 같은 커밋). 에이전트가 서버 요청을 받아 이 도구만 실행
echo '$PE_PY' | base64 -d > /opt/patchscope/plan-export/plan_export.py
echo '$PE_SH' | base64 -d > /opt/patchscope/plan-export/patchscope-plan-export
chmod 0755 /opt/patchscope/plan-export/patchscope-plan-export
chmod 0644 /opt/patchscope/plan-export/plan_export.py
echo "installed \$(/opt/patchscope/bin/patchscope-agent version)"
if systemctl is-enabled patchscope-agent >/dev/null 2>&1; then systemctl restart patchscope-agent; echo "agent restarted"; fi
EOF
for h in "$@"; do
  echo "=== $h"
  bash "$DIR/ssm-run.sh" "$h" "$TMP" 120 < /dev/null
done
rm -f "$TMP"
