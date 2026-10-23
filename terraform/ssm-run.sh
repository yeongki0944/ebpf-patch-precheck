#!/usr/bin/env bash
# SSM Run Command 로 원격 스크립트 실행 후 결과 출력
#   ./ssm-run.sh <host_key|instance-id> <script-file | -> [timeout_sec]
#   예) ./ssm-run.sh rhel8 ./probe.sh
#       echo 'uname -r' | ./ssm-run.sh analysis -
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE="${PROFILE:-$(grep -E '^\s*aws_profile' "$DIR/terraform.tfvars" 2>/dev/null | sed -E 's/.*"(.*)".*/\1/' | tr -d '\r')}"
REGION="${REGION:-ap-northeast-2}"
for v in AWS_REGION AWS_DEFAULT_REGION; do [ -z "${!v:-}" ] && unset "$v"; done
AWS=(aws --profile "$PROFILE" --region "$REGION" --output text)

TARGET="${1:?host_key 또는 instance-id}"
SRC="${2:?스크립트 파일 또는 -}"
TIMEOUT="${3:-600}"

if [[ "$TARGET" =~ ^i-[0-9a-f]+$ ]]; then ID="$TARGET"
else ID=$(cd "$DIR" && terraform output -json instance_ids | python -c "import sys,json;print(json.load(sys.stdin)['$TARGET'])" | tr -d '\r'); fi

if [ "$SRC" = "-" ]; then BODY=$(cat); else BODY=$(cat "$SRC"); fi
B64=$(printf '%s' "$BODY" | base64 -w0)

CMD_ID=$("${AWS[@]}" ssm send-command --instance-ids "$ID" --document-name AWS-RunShellScript \
  --timeout-seconds "$TIMEOUT" \
  --parameters "{\"commands\":[\"echo $B64 | base64 -d > /tmp/ssm-run.sh && bash /tmp/ssm-run.sh; rc=\$?; rm -f /tmp/ssm-run.sh; exit \$rc\"],\"executionTimeout\":[\"$TIMEOUT\"]}" \
  --query Command.CommandId | tr -d '\r')
[ -n "$CMD_ID" ] || { echo "[ERROR] send-command 실패" >&2; exit 1; }

END=$(( $(date +%s) + TIMEOUT + 30 ))
while :; do
  sleep 3
  ST=$("${AWS[@]}" ssm get-command-invocation --command-id "$CMD_ID" --instance-id "$ID" --query Status 2>/dev/null | tr -d '\r')
  case "$ST" in Pending|InProgress|Delayed|"") [ "$(date +%s)" -lt "$END" ] && continue ;; esac
  break
done
# 출력이 24000자를 넘으면 잘림 -> 큰 결과는 원격 파일로 남기고 요약만 출력할 것
"${AWS[@]}" ssm get-command-invocation --command-id "$CMD_ID" --instance-id "$ID" --query StandardOutputContent | tr -d '\r'
ERR=$("${AWS[@]}" ssm get-command-invocation --command-id "$CMD_ID" --instance-id "$ID" --query StandardErrorContent | tr -d '\r')
[ -n "$ERR" ] && [ "$ERR" != "None" ] && echo "--- stderr ---" >&2 && echo "$ERR" >&2
echo "[ssm-run] $TARGET status=$ST" >&2
[ "$ST" = "Success" ]
