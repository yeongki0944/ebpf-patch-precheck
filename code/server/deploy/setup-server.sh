#!/bin/bash
# analysis 호스트에서 root 로 실행 (멱등). /opt/patchscope 레포 기준.
#  - PoC CA (개인키는 이 호스트 /etc/patchscope-ca 에만 존재, 0600)
#  - 서버 인증서: SAN = private DNS + private IP
#  - PostgreSQL(peer 인증), venv, systemd(uvicorn 127.0.0.1:8000), nginx TLS 443
#  - 관리자 비밀번호: 없으면 생성해 /root/patchscope-admin-password (0600) 에만 저장
set -euo pipefail
REPO=/opt/patchscope
PY=$(cat /var/lib/patchscope/python)          # bootstrap 이 기록 (python3.12)
PG=$(cat /var/lib/patchscope/postgres)        # postgresql17
CA_DIR=/etc/patchscope-ca
CFG=/etc/patchscope-server
APP_USER=patchscope

TOKEN=$(curl -sX PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')
md() { curl -s -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/meta-data/$1"; }
PDNS=$(md local-hostname)
PIP=$(md local-ipv4)

# ---- user / dirs
id "$APP_USER" >/dev/null 2>&1 || useradd --system --home /var/lib/patchscope-server --shell /sbin/nologin "$APP_USER"
install -d -m 0750 -o root -g "$APP_USER" "$CFG"
install -d -m 0700 "$CA_DIR"

# ---- CA + server cert
if [ ! -f "$CA_DIR/ca.key" ]; then
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$CA_DIR/ca.key"
  chmod 600 "$CA_DIR/ca.key"
  openssl req -x509 -new -key "$CA_DIR/ca.key" -sha256 -days 365 -subj "/CN=PatchScope PoC CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$CA_DIR/ca.crt"
fi
if [ ! -f "$CFG/server.crt" ] || ! openssl x509 -in "$CFG/server.crt" -noout -ext subjectAltName 2>/dev/null | grep -q "$PDNS"; then
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$CFG/server.key"
  openssl req -new -key "$CFG/server.key" -subj "/CN=$PDNS" -out /tmp/server.csr
  cat > /tmp/server.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:$PDNS,IP:$PIP
EOF
  openssl x509 -req -in /tmp/server.csr -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" -CAcreateserial \
    -days 180 -sha256 -extfile /tmp/server.ext -out "$CFG/server.crt"
  rm -f /tmp/server.csr /tmp/server.ext
fi
chown root:nginx "$CFG/server.key" "$CFG/server.crt"; chmod 0640 "$CFG/server.key"; chmod 0644 "$CFG/server.crt"
cp "$CA_DIR/ca.crt" "$CFG/ca.crt"; chmod 0644 "$CFG/ca.crt"

# ---- session key / admin password
[ -f "$CFG/session.key" ] || { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$CFG/session.key"; }
chown root:"$APP_USER" "$CFG/session.key"; chmod 0640 "$CFG/session.key"

# ---- PostgreSQL (peer 인증: OS 사용자 patchscope = DB role patchscope)
if [ ! -f /var/lib/pgsql/data/PG_VERSION ]; then
  postgresql-setup --initdb
fi
systemctl enable --now postgresql
sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$APP_USER'" | grep -q 1 \
  || sudo -u postgres createuser "$APP_USER"
sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='patchscope'" | grep -q 1 \
  || sudo -u postgres createdb -O "$APP_USER" patchscope

# ---- venv
if [ ! -x /opt/patchscope-venv/bin/python ]; then
  "$PY" -m venv /opt/patchscope-venv
fi
/opt/patchscope-venv/bin/pip install -q --upgrade pip
/opt/patchscope-venv/bin/pip install -q -r "$REPO/code/server/requirements.txt"
/opt/patchscope-venv/bin/pip freeze > /var/lib/patchscope/server-requirements.lock

if [ ! -f "$CFG/admin.hash" ]; then
  PW=$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 20)
  umask 077
  printf '%s\n' "$PW" > /root/patchscope-admin-password
  printf '%s\n' "$PW" | /opt/patchscope-venv/bin/python -c "import sys; sys.path.insert(0,'$REPO/code/server'); from patchscope_server.auth import hash_password; print(hash_password(sys.stdin.readline().strip()))" > "$CFG/admin.hash"
  unset PW
fi
chown root:"$APP_USER" "$CFG/admin.hash"; chmod 0640 "$CFG/admin.hash"

# 관리 CLI 를 patchscope 사용자로 실행하는 래퍼 (peer 인증)
cat > /usr/local/sbin/patchscope-admin <<EOF
#!/bin/bash
cd $REPO/code/server && exec sudo -u $APP_USER /opt/patchscope-venv/bin/python -m patchscope_server.cli "\$@"
EOF
chmod 0750 /usr/local/sbin/patchscope-admin
patchscope-admin init

# ---- systemd
cat > /etc/systemd/system/patchscope-server.service <<EOF
[Unit]
Description=PatchScope analysis server
After=network.target postgresql.service
Requires=postgresql.service

[Service]
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$REPO/code/server
ExecStart=/opt/patchscope-venv/bin/uvicorn patchscope_server.main:app --host 127.0.0.1 --port 8000 --proxy-headers --forwarded-allow-ips 127.0.0.1
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadOnlyPaths=$CFG

[Install]
WantedBy=multi-user.target
EOF

# ---- nginx (TLS 종료)
cat > /etc/nginx/conf.d/patchscope.conf <<EOF
server {
    listen 443 ssl;
    http2 on;
    server_name $PDNS $PIP;
    ssl_certificate     $CFG/server.crt;
    ssl_certificate_key $CFG/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 64m;
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 120s;
    }
}
EOF
# 기본 80 서버 비활성화 (SG 에서도 80 미개방)
sed -i 's/^\(\s*\)listen\s\+80/\1# listen 80/; s/^\(\s*\)listen\s\+\[::\]:80/\1# listen [::]:80/' /etc/nginx/nginx.conf
nginx -t
systemctl daemon-reload
systemctl enable --now patchscope-server nginx
systemctl restart patchscope-server nginx
sleep 2
curl -fsS --cacert "$CFG/ca.crt" "https://$PDNS/api/v1/health"; echo
echo "server_url=https://$PDNS"
echo "ca_sha256=$(sha256sum "$CFG/ca.crt" | cut -d' ' -f1)"
