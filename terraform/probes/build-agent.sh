#!/bin/bash
# analysis 서버: 최신 main 을 받아 에이전트 빌드·테스트 후 S3 업로드
#   BUCKET 환경변수 필요 (ssm-run 에서는 첫 줄에 export 로 주입)
set -euo pipefail
export HOME=/root PATH=$PATH:/usr/local/go/bin GOFLAGS=-mod=readonly GOCACHE=/root/.cache/go-build
cd /opt/patchscope
git fetch -q origin main && git reset -q --hard origin/main
echo "commit=$(git rev-parse --short HEAD)"
cd code/agent
rm -f bin/patchscope-agent   # 버전 문자열이 항상 현재 커밋을 가리키도록 재링크
make bin/patchscope-agent 2>&1 | tail -20
go vet ./... 2>&1 | tail -20
go test ./... 2>&1 | tail -20
ls -l bin/patchscope-agent
file bin/patchscope-agent 2>/dev/null || true
REV=$(git rev-parse --short HEAD)
if [ -n "${BUCKET:-}" ]; then
  sha256sum bin/patchscope-agent | tee bin/patchscope-agent.sha256
  aws s3 cp --quiet bin/patchscope-agent "s3://$BUCKET/agent/$REV/patchscope-agent"
  aws s3 cp --quiet bin/patchscope-agent.sha256 "s3://$BUCKET/agent/$REV/patchscope-agent.sha256"
  echo "uploaded s3://$BUCKET/agent/$REV/"
fi
echo "--- local precheck on analysis host"
./bin/patchscope-agent precheck --spool /tmp/ps-spool || true
