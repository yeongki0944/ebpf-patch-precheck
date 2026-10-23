#!/usr/bin/env bash
# 3대 EC2 의 SSM 등록 + bootstrap 완료 확인, 기준 manifest 요약 출력
#   ./check-ready.sh            (먼저 ./sso-login.sh)
set -uo pipefail

# 프로필: 환경변수 > terraform.tfvars 의 aws_profile
PROFILE="${PROFILE:-$(grep -E '^\s*aws_profile' "$(dirname "$0")/terraform.tfvars" 2>/dev/null | sed -E 's/.*"(.*)".*/\1/' | tr -d '\r')}"
REGION="${REGION:-ap-northeast-2}"
TIMEOUT="${TIMEOUT:-1800}"
INTERVAL="${INTERVAL:-20}"
for v in AWS_REGION AWS_DEFAULT_REGION; do [ -z "${!v:-}" ] && unset "$v"; done

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AWS=(aws --profile "$PROFILE" --region "$REGION" --output text)
log() { echo "[$(date '+%H:%M:%S')] $*"; }
die() { log "[ERROR] $*"; exit 1; }

"${AWS[@]}" sts get-caller-identity >/dev/null 2>&1 || die "자격증명 없음/만료. ./sso-login.sh 실행"
IDS_JSON=$(cd "$DIR" && terraform output -json instance_ids 2>/dev/null | tr -d '\r')
[ -n "$IDS_JSON" ] || die "terraform output 없음. apply 여부 확인"
mapfile -t KEYS < <(echo "$IDS_JSON" | python -c "import sys,json;[print(k) for k in json.load(sys.stdin)]" | tr -d '\r')
id_of() { echo "$IDS_JSON" | python -c "import sys,json;print(json.load(sys.stdin)['$1'])" | tr -d '\r'; }

REMOTE='S=/var/lib/patchscope; B=$S/baseline
echo "kernel=$(cat $B/kernel_release 2>/dev/null) btf=$(cat $B/btf 2>/dev/null)"
echo "os=$(. /etc/os-release; echo $PRETTY_NAME) rpms=$(wc -l < $B/rpm-qa.txt 2>/dev/null)"
[ -f $S/toolchain.txt ] && sed "s/^/  /" $S/toolchain.txt
[ -f $S/go-version ] && echo "  go=$(cat $S/go-version)"
if [ -f $S/error ]; then echo "RESULT=FAIL $(cat $S/error)"; tail -15 /var/log/patchscope-init.log
elif [ -f $S/ready ]; then echo RESULT=READY
else echo "RESULT=WAIT last: $(grep "^+ " /var/log/patchscope-init.log | tail -1 | cut -c1-90)"; fi'
REMOTE_B64=$(printf '%s' "$REMOTE" | base64 -w0)

run_remote() {
  local id=$1 cmd st
  cmd=$("${AWS[@]}" ssm send-command --instance-ids "$id" --document-name AWS-RunShellScript \
    --parameters "commands=[\"echo $REMOTE_B64 | base64 -d | bash\"]" --query Command.CommandId 2>/dev/null | tr -d '\r')
  [ -n "$cmd" ] || { echo "RESULT=WAIT send-command 실패"; return; }
  for _ in $(seq 1 20); do
    sleep 2
    st=$("${AWS[@]}" ssm get-command-invocation --command-id "$cmd" --instance-id "$id" --query Status 2>/dev/null | tr -d '\r')
    case "$st" in Pending|InProgress|Delayed|"") ;; *) break ;; esac
  done
  "${AWS[@]}" ssm get-command-invocation --command-id "$cmd" --instance-id "$id" --query StandardOutputContent 2>/dev/null | tr -d '\r'
}

declare -A DONE=()
START=$(date +%s)
while :; do
  for k in "${KEYS[@]}"; do
    [ -n "${DONE[$k]:-}" ] && continue
    id=$(id_of "$k")
    ping=$("${AWS[@]}" ssm describe-instance-information --filters "Key=InstanceIds,Values=$id" \
      --query 'InstanceInformationList[0].PingStatus' 2>/dev/null | tr -d '\r')
    if [ "$ping" != "Online" ]; then log "$k ($id): SSM ${ping:-미등록}"; continue; fi
    out=$(run_remote "$id")
    res=$(echo "$out" | grep -o 'RESULT=[A-Z]*' | tail -1 | cut -d= -f2)
    log "$k ($id): ${res:-WAIT}"
    echo "$out" | grep -v '^RESULT=READY' | sed 's/^/      /'
    case "$res" in READY) DONE[$k]=ok ;; FAIL) DONE[$k]=fail ;; esac
  done
  [ "${#DONE[@]}" -eq "${#KEYS[@]}" ] && break
  [ $(( $(date +%s) - START )) -ge "$TIMEOUT" ] && die "타임아웃"
  sleep "$INTERVAL"
done

for k in "${KEYS[@]}"; do [ "${DONE[$k]}" = fail ] && die "$k bootstrap 실패"; done
log "전체 READY ($(( $(date +%s) - START ))s)"
