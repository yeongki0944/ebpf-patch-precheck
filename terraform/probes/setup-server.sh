#!/bin/bash
set -euo pipefail
cd /opt/patchscope
git fetch -q origin main && git reset -q --hard origin/main
echo "commit=$(git rev-parse --short HEAD)"
bash code/server/deploy/setup-server.sh
install -m 0755 code/plan-export/patchscope-plan-export /usr/local/bin/ 2>/dev/null || true
