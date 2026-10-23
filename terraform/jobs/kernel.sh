#!/usr/bin/env bash
# 커널 패치 시험: kernel plan → 분석 → 설치 → 재부팅 → SSM 복귀 대기 → 검증 → 서버에서 boot_id/세션 확인
set -uo pipefail
cd "$(dirname "$0")/.."
PROFILE=$(grep -E '^\s*aws_profile' terraform.tfvars | sed -E 's/.*"(.*)".*/\1/' | tr -d '\r')
AWS=(aws --profile "$PROFILE" --region ap-northeast-2 --output text)
for v in AWS_REGION AWS_DEFAULT_REGION; do [ -z "${!v:-}" ] && unset "$v"; done
ID() { terraform output -json instance_ids | python -c "import sys,json;print(json.load(sys.stdin)['$1'])" | tr -d '\r'; }
run() { bash ./ssm-run.sh "$@" < /dev/null 2>&1; }
declare -A RV=( [rhel8]="" [al2023]="latest" )

for h in rhel8 al2023; do
  echo "######## $h kernel plan + analysis"
  KERNEL=1 RELEASEVER="${RV[$h]}" LABEL="$h kernel" bash ./plan-export.sh "$h" 2>&1 | grep -E '^plan|coverage|kernel:|warn|ERROR' | head -10
  echo "######## $h install + reboot"
  { echo "export RELEASEVER='${RV[$h]}'"; cat probes/kernel-apply.sh; } > /tmp/ps-k.sh
  run "$h" /tmp/ps-k.sh 900
  rm -f /tmp/ps-k.sh
  sleep 60
  id=$(ID "$h")
  for i in $(seq 1 40); do
    st=$("${AWS[@]}" ssm describe-instance-information --filters "Key=InstanceIds,Values=$id" --query 'InstanceInformationList[0].PingStatus' | tr -d '\r')
    [ "$st" = Online ] && break
    sleep 15
  done
  echo "ssm after reboot: $st (${i}x15s)"
  sleep 30
  echo "######## $h post-reboot checks"
  run "$h" probes/kernel-postcheck.sh 120
done
echo "######## server view"
cat > /tmp/ps-q.sh <<'EOF'
sudo -u patchscope psql -d patchscope -tA -F ' | ' -c "SELECT hostname, kernel, left(boot_id,8), capability_status FROM hosts ORDER BY 1"
sudo -u patchscope psql -d patchscope -tA -F ' | ' -c "SELECT h.hostname, left(s.boot_id,8), s.kernel, count(*) FROM sessions s JOIN hosts h USING(host_id) GROUP BY 1,2,3 ORDER BY 1, min(s.first_window_start)"
EOF
run analysis /tmp/ps-q.sh 60
rm -f /tmp/ps-q.sh
