#!/usr/bin/env bash
# 1) 분석 서버에 nginx :80 (CloudFront 전용) 추가 → 2) terraform apply (VPC origin + 배포 + SG) → 3) 접속 확인
set -uo pipefail
cd "$(dirname "$0")/.."
for v in AWS_REGION AWS_DEFAULT_REGION; do [ -z "${!v:-}" ] && unset "$v"; done
echo "######## setup-server (nginx :80 for CloudFront)"
bash ./ssm-run.sh analysis probes/setup-server.sh 600 < /dev/null 2>&1 | tail -3
# probe VPC origin 삭제 완료 대기 (같은 인스턴스에 중복 방지)
for i in $(seq 1 40); do
  s=$(timeout 25 aws cloudfront get-vpc-origin --profile younggikim_poc --region us-east-1 --id vo_K3vJaRXHpsuDaD6olFDBYr --query 'VpcOrigin.Status' --output text 2>&1)
  echo "$(date +%T) probe vpc origin: ${s:0:60}"
  echo "$s" | grep -q 'NoSuchVpcOrigin\|EntityNotFound\|not found\|does not exist' && break
  [ "$s" = "Deploying" ] || [ "$s" = "Deployed" ] || break
  sleep 30
done
echo "######## terraform apply"
terraform plan -input=false -no-color -out=tf.tfplan 2>&1 | grep -E '^  # |Plan:|Error'
terraform apply -input=false -no-color tf.tfplan 2>&1 | grep -E 'complete|Error|error' | tail -12
rm -f tf.tfplan
URL=$(terraform output -raw web_url | tr -d '\r')
echo "web_url=$URL"
for i in $(seq 1 20); do
  c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 "$URL/login")
  echo "$(date +%T) GET /login -> $c"
  [ "$c" = 200 ] && break; sleep 30
done
echo "api via CF (expect 403): $(curl -s -o /dev/null -w '%{http_code}' --max-time 15 "$URL/api/v1/health")"
echo "http redirect (expect 301): $(curl -s -o /dev/null -w '%{http_code}' --max-time 15 "${URL/https/http}/login")"
echo "cache headers: $(curl -sI --max-time 15 "$URL/login" | grep -iE 'x-cache|cache-control' | tr -d '\r' | paste -sd' ')"
PUB=$(terraform output -json instance_ids | python -c "import sys,json;print(json.load(sys.stdin)['analysis'])" | tr -d '\r')
IP=$(aws ec2 describe-instances --profile younggikim_poc --region ap-northeast-2 --instance-ids "$PUB" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text | tr -d '\r')
echo "direct public 443 (expect timeout 000): $(curl -sk -o /dev/null -w '%{http_code}' --max-time 8 "https://$IP/login")"
echo "direct public 80  (expect timeout 000): $(curl -s -o /dev/null -w '%{http_code}' --max-time 8 "http://$IP/login")"
echo "agents still sending:"
echo 'sudo -u patchscope psql -d patchscope -tA -c "SELECT hostname, now()-last_seen FROM hosts ORDER BY 1"' > /tmp/q.sh
bash ./ssm-run.sh analysis /tmp/q.sh 60 < /dev/null 2>&1 | head -3; rm -f /tmp/q.sh
