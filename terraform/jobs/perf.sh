#!/usr/bin/env bash
cd "$(dirname "$0")/.."
for h in al2023 rhel8; do
  echo "######## perf $h"
  bash ./ssm-run.sh "$h" probes/perf-bench.sh 900 < /dev/null 2>&1 | grep -vE '^\{"mode"' 
done
