#!/bin/bash
# 대상 호스트: 테스트 작업 부하 설치 (공식 OS 저장소, 현재 releasever 고정 - 패치하지 않음)
#   nginx, redis, python 배치(systemd timer), curl/openssl CLI 작업
# AL2023 은 releasever 가 AMI 에 고정되어 있어 같은 시점의 구버전 패키지가 설치된다.
set -euo pipefail
export DNF_NOTIFY=0
. /etc/os-release
M=/var/lib/patchscope/baseline/workload-manifest.txt

if [ "$ID" = "amzn" ]; then
  dnf install -q -y nginx redis6 >/dev/null
  REDIS=redis6
else
  # RHEL 8 은 python3 가 기본 미설치 (platform-python 만 있음) → python3 (3.6, AppStream) 설치
  dnf install -q -y nginx python3 >/dev/null
  dnf module enable -q -y redis:6 >/dev/null 2>&1 || true
  dnf install -q -y redis >/dev/null
  REDIS=redis
fi
systemctl enable --now nginx "$REDIS" >/dev/null

# python 배치: 1분마다 실행, hashlib/ssl 사용 (OpenSSL 라이브러리 로드), 짧게 종료
cat > /usr/local/bin/ps-batch.py <<'PY'
#!/usr/bin/env python3
import hashlib, json, ssl, sqlite3, urllib.request
ctx = ssl.create_default_context()
db = sqlite3.connect("/var/tmp/ps-batch.db")
db.execute("CREATE TABLE IF NOT EXISTS t (k TEXT, v TEXT)")
db.execute("INSERT INTO t VALUES (?, ?)", ("run", hashlib.sha256(b"x").hexdigest()))
db.commit()
body = urllib.request.urlopen("http://127.0.0.1/", timeout=5).read()
print(json.dumps({"bytes": len(body), "tls": ssl.OPENSSL_VERSION}))
PY
chmod 0755 /usr/local/bin/ps-batch.py
cat > /etc/systemd/system/ps-batch.service <<'U'
[Unit]
Description=PatchScope test batch
[Service]
Type=oneshot
ExecStart=/usr/local/bin/ps-batch.py
U
cat > /etc/systemd/system/ps-batch.timer <<'U'
[Unit]
Description=PatchScope test batch every minute
[Timer]
OnCalendar=*:*:00
AccuracySec=1s
[Install]
WantedBy=timers.target
U
# CLI 작업: curl + openssl, 1분마다
cat > /etc/systemd/system/ps-cli.service <<'U'
[Unit]
Description=PatchScope curl/openssl CLI job
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'curl -fsS -o /dev/null http://127.0.0.1/ && openssl dgst -sha256 /etc/hostname >/dev/null && redis-cli ping >/dev/null 2>&1 || redis6-cli ping >/dev/null'
U
cat > /etc/systemd/system/ps-cli.timer <<'U'
[Unit]
Description=PatchScope CLI job every minute
[Timer]
OnCalendar=*:*:30
AccuracySec=1s
[Install]
WantedBy=timers.target
U
systemctl daemon-reload
systemctl enable --now ps-batch.timer ps-cli.timer >/dev/null
systemctl start ps-batch.service ps-cli.service
{
  date -u +%FT%TZ
  rpm -q nginx "$REDIS" python3 curl openssl openssl-libs glibc 2>/dev/null || true
  /usr/local/bin/ps-batch.py
} > "$M" 2>&1
cat "$M"
systemctl is-active nginx "$REDIS" ps-batch.timer ps-cli.timer | paste -sd' '
