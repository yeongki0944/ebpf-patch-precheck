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
  bash ./ssm-run.sh analysis /tmp/ps-ui.sh 900 < /dev/null 2>&1
done
rm -f /tmp/ps-ui.sh
