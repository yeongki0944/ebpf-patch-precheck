#!/usr/bin/env bash
# 실제 패치 수행 (사용자 승인: 스냅샷 생략)
#   서버 업데이트 → 에이전트 배포 → [대상별] 패치 전 작업 → 패키지 패치(--comment) → 부분 재시작 → 패치 후 작업
#   → 커널 업데이트 → 재부팅 → SSM 복귀 → 재부팅 후 확인 → 서버에서 변경 작업 페이지 확인
set -uo pipefail
cd "$(dirname "$0")/.."
PROFILE=$(grep -E '^\s*aws_profile' terraform.tfvars | sed -E 's/.*"(.*)".*/\1/' | tr -d '\r')
AWS=(aws --profile "$PROFILE" --region ap-northeast-2 --output text)
for v in AWS_REGION AWS_DEFAULT_REGION; do [ -z "${!v:-}" ] && unset "$v"; done
ID() { terraform output -json instance_ids | python -c "import sys,json;print(json.load(sys.stdin)['$1'])" | tr -d '\r'; }
run() { bash ./ssm-run.sh "$@" < /dev/null 2>&1; }
log() { echo "[$(date '+%H:%M:%S')] $*"; }

declare -A PK=( [rhel8]="openssl-libs openssl glibc glibc-common glibc-langpack-en glibc-gconv-extra" [al2023]="openssl-libs openssl" )
declare -A RV=( [rhel8]="" [al2023]="latest" )

log "######## update server + deploy agent"
run analysis probes/update-server.sh 300 | tail -1
SKIP_SMOKE=1 bash ./pipeline.sh 2>&1 | grep -E 'installed|restarted|rror' | head -6
sleep 90

for h in rhel8 al2023; do
  log "######## $h: before workload"
  run "$h" probes/workload-run.sh 300
  sleep 60
  PLAN=$(echo "sudo -u patchscope psql -d patchscope -tA -c \"SELECT max(id) FROM patch_plans p JOIN hosts h USING(host_id) WHERE h.hostname='patchscope-$h' AND plan_type='packages'\"" > /tmp/q.sh; run analysis /tmp/q.sh 60 | head -1 | tr -d ' \r')
  log "######## $h: package patch (plan #$PLAN)"
  { echo "export PKGS='${PK[$h]}' RELEASEVER='${RV[$h]}' COMMENT='PatchScope PoC 보안패치 / 계획 #$PLAN / 작업: kiro'"; cat probes/patch-apply.sh; } > /tmp/ps-apply.sh
  run "$h" /tmp/ps-apply.sh 900
  log "######## $h: after workload (agent rescans stale mappings every 60s)"
  sleep 90
  run "$h" probes/workload-run.sh 300
  sleep 60
done

for h in rhel8 al2023; do
  log "######## $h: kernel update + reboot"
  { echo "export RELEASEVER='${RV[$h]}'"; cat probes/kernel-apply.sh; } > /tmp/ps-k.sh
  run "$h" /tmp/ps-k.sh 900
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
rm -f /tmp/ps-apply.sh /tmp/ps-k.sh /tmp/q.sh

sleep 60
log "######## server view"
cat > /tmp/ps-v.sh <<'EOF'
q() { sudo -u patchscope psql -d patchscope -tA -F ' | ' -c "$1"; }
q "SELECT h.hostname, t.tid, t.begin_at, coalesce(t.username,'-'), left(coalesce(t.comment,''),50), left(t.cmdline,60), jsonb_array_length(t.items) FROM pkg_transactions t JOIN hosts h USING(host_id) WHERE t.begin_at > now() - interval '3 hours' ORDER BY t.begin_at"
q "SELECT h.hostname, unit, comm, count(*) FROM records r JOIN hosts h USING(host_id) WHERE kind='stale_mapping' AND ts_utc > now() - interval '3 hours' GROUP BY 1,2,3 ORDER BY 1,4 DESC LIMIT 15"
q "SELECT hostname, kernel, left(boot_id,8), capability_status, last_seen FROM hosts ORDER BY 1"
EOF
run analysis /tmp/ps-v.sh 120 | cut -c1-220
rm -f /tmp/ps-v.sh
