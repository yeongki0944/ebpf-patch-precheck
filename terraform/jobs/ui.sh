#!/usr/bin/env bash
# 서버 업데이트 → 에이전트 빌드·배포(plan-export 포함) → UI 흐름 E2E
cd "$(dirname "$0")/.."
echo "######## update server"
bash ./ssm-run.sh analysis probes/update-server.sh 300 < /dev/null 2>&1 | tail -3
echo "######## build + deploy agent"
SKIP_SMOKE=1 bash ./pipeline.sh 2>&1 | grep -E 'installed|restarted|status=|rror' | head -20
sleep 30
for h in "rhel8:patchscope-rhel8:openssl-libs glibc" "al2023:patchscope-al2023:openssl-libs"; do
  IFS=: read -r key name pk <<<"$h"
  echo "######## ui flow $name"
  { echo "export HOSTNAME_FILTER='$name' PKGS='$pk'"; cat probes/ui-flow.sh; } > /tmp/ps-ui.sh
  bash ./ssm-run.sh analysis /tmp/ps-ui.sh 900 < /dev/null 2>&1 | grep -av '^ *[0-9]* bytes' | grep -aE 'login|200|list_updates|resolve_plan|updates:|checkboxes|= |service|csrf|package|without|^[a-z]' | cut -c1-300
  echo "--- agent side"
  bash ./ssm-run.sh "$key" probes/oom-check.sh 60 < /dev/null 2>&1 | tail -6
done
rm -f /tmp/ps-ui.sh
