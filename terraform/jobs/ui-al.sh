#!/usr/bin/env bash
cd "$(dirname "$0")/.."
bash ./ssm-run.sh analysis probes/update-server.sh 300 < /dev/null 2>&1 | tail -2
for h in "al2023:patchscope-al2023:openssl-libs" "rhel8:patchscope-rhel8:openssl-libs glibc"; do
  IFS=: read -r key name pk <<<"$h"
  echo "######## ui flow $name"
  { echo "export HOSTNAME_FILTER='$name' PKGS='$pk'"; cat probes/ui-flow.sh; } > /tmp/ps-ui.sh
  bash ./ssm-run.sh analysis /tmp/ps-ui.sh 900 < /dev/null 2>&1 | grep -av '^ *[0-9]* bytes' | cut -c1-300
done
bash ./ssm-run.sh analysis probes/ui-debug.sh 60 < /dev/null 2>&1 | tail -6
rm -f /tmp/ps-ui.sh
