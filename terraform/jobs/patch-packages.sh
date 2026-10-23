#!/usr/bin/env bash
# 패키지 패치 전후 비교 시험 (두 대상)
#  0) EBS 스냅샷 (복원 지점)
#  1) 패치 전: 같은 작업 수행 → 세션 A 를 닫기 위해 에이전트 재시작
#  2) plan-export → 분석 (패치 전 인벤토리 기준)
#  3) 실제 dnf upgrade (같은 패키지, AL2023 은 같은 releasever)
#  4) 패치 후: 에이전트 재시작(새 세션 B) → 같은 작업 수행
#  5) 서버에서 A/B 비교
set -uo pipefail
cd "$(dirname "$0")/.."
PROFILE=$(grep -E '^\s*aws_profile' terraform.tfvars | sed -E 's/.*"(.*)".*/\1/' | tr -d '\r')
AWS=(aws --profile "$PROFILE" --region ap-northeast-2 --output text)
for v in AWS_REGION AWS_DEFAULT_REGION; do [ -z "${!v:-}" ] && unset "$v"; done
ID() { terraform output -json instance_ids | python -c "import sys,json;print(json.load(sys.stdin)['$1'])" | tr -d '\r'; }
run() { bash ./ssm-run.sh "$@" < /dev/null 2>&1; }

declare -A PK=( [rhel8]="openssl-libs openssl glibc" [al2023]="openssl-libs openssl" )
declare -A RV=( [rhel8]="" [al2023]="latest" )

echo "######## 0) snapshots"
for h in al2023 rhel8; do
  vol=$("${AWS[@]}" ec2 describe-instances --instance-ids "$(ID $h)" --query 'Reservations[0].Instances[0].BlockDeviceMappings[0].Ebs.VolumeId' | tr -d '\r')
  snap=$("${AWS[@]}" ec2 create-snapshot --volume-id "$vol" --description "patchscope $h before package patch" \
    --tag-specifications "ResourceType=snapshot,Tags=[{Key=Project,Value=patchscope},{Key=Name,Value=patchscope-$h-prepatch}]" \
    --query SnapshotId | tr -d '\r')
  echo "$h volume=$vol snapshot=$snap"
done

for h in rhel8 al2023; do
  echo "######## $h 1) before workload"
  run "$h" probes/workload-run.sh 300
  sleep 30
  echo 'systemctl restart patchscope-agent; sleep 20; journalctl -u patchscope-agent -n 3 -o cat --no-pager' > /tmp/ps-r.sh
  run "$h" /tmp/ps-r.sh 120    # 세션 A 종료(shutdown flush) → 새 세션 시작

  echo "######## $h 2) plan + analysis (pre-patch inventory)"
  RELEASEVER="${RV[$h]}" LABEL="$h pre-patch ${PK[$h]}" bash ./plan-export.sh "$h" ${PK[$h]} 2>&1 | grep -vE '^\s{6}' | head -30

  echo "######## $h 3) apply"
  { echo "export PKGS='${PK[$h]}' RELEASEVER='${RV[$h]}'"; cat probes/patch-apply.sh; } > /tmp/ps-apply.sh
  run "$h" /tmp/ps-apply.sh 900

  echo "######## $h 4) after: new session + same workload"
  run "$h" /tmp/ps-r.sh 120
  run "$h" probes/workload-run.sh 300
  sleep 30
  run "$h" /tmp/ps-r.sh 120    # 세션 B flush
done
rm -f /tmp/ps-r.sh /tmp/ps-apply.sh
echo "######## 5) compare on server"
run analysis probes/compare-sessions.sh 300
