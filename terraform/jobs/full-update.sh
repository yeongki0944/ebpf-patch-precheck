#!/usr/bin/env bash
# 전체 업데이트 시험 (사용자 승인, 스냅샷 생략)
#   [대상별] 패치 전 작업 → dnf upgrade(전체, --comment) → 3분 대기(재시작 필요 관측) → 재부팅 → SSM 복귀 → 재부팅 후 확인 → 패치 후 작업
set -uo pipefail
cd "$(dirname "$0")/.."
PROFILE=$(grep -E '^\s*aws_profile' terraform.tfvars | sed -E 's/.*"(.*)".*/\1/' | tr -d '\r')
AWS=(aws --profile "$PROFILE" --region ap-northeast-2 --output text)
for v in AWS_REGION AWS_DEFAULT_REGION; do [ -z "${!v:-}" ] && unset "$v"; done
ID() { terraform output -json instance_ids | python -c "import sys,json;print(json.load(sys.stdin)['$1'])" | tr -d '\r'; }
run() { bash ./ssm-run.sh "$@" < /dev/null 2>&1; }
log() { echo "[$(date '+%H:%M:%S')] $*"; }
declare -A RV=( [rhel8]="" [al2023]="latest" )

for h in rhel8 al2023; do
  log "######## $h: before workload"
  run "$h" probes/workload-run.sh 300
  sleep 60
  log "######## $h: full update"
  { echo "export RELEASEVER='${RV[$h]}' COMMENT='PatchScope PoC 전체 업데이트 / 작업: kiro'"; cat probes/full-update.sh; } > /tmp/ps-fu.sh
  run "$h" /tmp/ps-fu.sh 1800
  log "######## $h: wait 3m (agent rescans stale mappings) then reboot"
  sleep 180
  echo 'systemd-run --on-active=10 --unit=ps-reboot /bin/systemctl reboot >/dev/null; echo reboot scheduled' > /tmp/ps-rb.sh
  run "$h" /tmp/ps-rb.sh 60
  id=$(ID "$h"); sleep 60
  for i in $(seq 1 40); do
    st=$("${AWS[@]}" ssm describe-instance-information --filters "Key=InstanceIds,Values=$id" --query 'InstanceInformationList[0].PingStatus' | tr -d '\r')
    [ "$st" = Online ] && break; sleep 15
  done
  log "$h ssm after reboot: $st"
  sleep 60
  log "######## $h: post-reboot checks + workload"
  run "$h" probes/kernel-postcheck.sh 120
  run "$h" probes/workload-run.sh 300
done
rm -f /tmp/ps-fu.sh /tmp/ps-rb.sh
sleep 60
log "######## server view (latest transactions)"
cat > /tmp/ps-v.sh <<'EOF'
q() { sudo -u patchscope psql -d patchscope -tA -F ' | ' -c "$1"; }
q "SELECT h.hostname, t.tid, t.begin_at, left(coalesce(t.comment,''),40), jsonb_array_length(t.items) FROM pkg_transactions t JOIN hosts h USING(host_id) ORDER BY t.begin_at DESC LIMIT 4"
q "SELECT h.hostname, count(DISTINCT unit), count(*) FROM records r JOIN hosts h USING(host_id) WHERE kind='stale_mapping' AND ts_utc > now() - interval '1 hour' GROUP BY 1"
q "SELECT hostname, kernel, left(boot_id,8), capability_status FROM hosts ORDER BY 1"
EOF
run analysis /tmp/ps-v.sh 120 | cut -c1-200
rm -f /tmp/ps-v.sh
