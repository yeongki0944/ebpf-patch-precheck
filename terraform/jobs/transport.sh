#!/usr/bin/env bash
cd "$(dirname "$0")/.."
for h in al2023 rhel8; do
  echo "######## transport $h"
  bash ./ssm-run.sh "$h" probes/transport-test.sh 900 < /dev/null 2>&1
done
echo "######## verify on server"
bash ./ssm-run.sh analysis probes/transport-verify.sh 120 < /dev/null 2>&1
