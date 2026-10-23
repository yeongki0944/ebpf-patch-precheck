#!/bin/bash
# analysis: 최신 코드 반영 후 서버 재시작
set -euo pipefail
cd /opt/patchscope
git fetch -q origin main && git reset -q --hard origin/main
echo "commit=$(git rev-parse --short HEAD)"
/opt/patchscope-venv/bin/pip install -q -r code/server/requirements.txt
patchscope-admin init
systemctl restart patchscope-server
sleep 2
curl -fsS --cacert /etc/patchscope-server/ca.crt "https://$(hostname -f)/api/v1/health" || \
  curl -fsS --cacert /etc/patchscope-server/ca.crt "https://$(curl -s -H "X-aws-ec2-metadata-token: $(curl -sX PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')" http://169.254.169.254/latest/meta-data/local-hostname)/api/v1/health"
echo
