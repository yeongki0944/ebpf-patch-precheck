#!/usr/bin/env bash
cd "$(dirname "$0")/.."
for h in al2023 rhel8; do
  echo "######## workload-complex $h"
  bash ./ssm-run.sh "$h" probes/workload-complex.sh 900 < /dev/null 2>&1
done
