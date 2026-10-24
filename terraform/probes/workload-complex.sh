#!/bin/bash
# 대상 호스트: 한 프로세스가 여러 OS 패키지를 쓰는 작업 부하 (패치하지 않음, 현재 releasever 고정)
#   php-fpm + 확장(gd, mbstring, xml, intl, pgsql, curl ...) : 프로세스 하나가 libpng/libjpeg/freetype/libxml2/ICU/libpq/libcurl/openssl 사용
#   postgresql                                               : 장기 실행 DB
#   ps-web.timer   (1분)  : nginx → php-fpm 엔드포인트 호출 (intl.php 는 일부러 호출 안 함)
#   ps-report.timer(2분)  : python 이 psycopg2(libpq) + lxml(libxml2/libxslt) + ssl 사용
#   ps-export.service     : 타이머 없음, 실행 안 함 (미실행 기능 = 관측 없음 확인용)
set -euo pipefail
export DNF_NOTIFY=0
. /etc/os-release
M=/var/lib/patchscope/baseline/workload-complex-manifest.txt
inst() { dnf install -q -y "$@" >/dev/null 2>&1; }

if [ "$ID" = amzn ]; then
  # AL2023 초기 릴리스: php8.1 계열. 이름이 없으면 php-* 로 재시도
  inst php8.1-fpm php8.1-cli php8.1-gd php8.1-mbstring php8.1-xml php8.1-intl php8.1-pgsql php8.1-opcache \
    || inst php-fpm php-cli php-gd php-mbstring php-xml php-intl php-pgsql php-opcache
  inst postgresql15-server postgresql15 || inst postgresql-server postgresql
  inst python3-psycopg2 python3-lxml
else
  inst php-fpm php-cli php-gd php-mbstring php-xml php-intl php-pgsql php-json php-opcache
  inst postgresql-server postgresql python3 python3-psycopg2 python3-lxml
fi

# ---- PostgreSQL (peer 인증, 앱 사용자 apache)
[ -f /var/lib/pgsql/data/PG_VERSION ] || postgresql-setup --initdb >/dev/null
systemctl enable --now postgresql >/dev/null
sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='apache'" | grep -q 1 || sudo -u postgres createuser apache
sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='app'" | grep -q 1 || sudo -u postgres createdb -O apache app
sudo -u apache psql -d app -qc "CREATE TABLE IF NOT EXISTS orders (id serial PRIMARY KEY, item text, qty int, created timestamptz DEFAULT now())"

# ---- PHP 앱
W=/usr/share/nginx/html/app
mkdir -p "$W"
cat > "$W/index.php" <<'PHP'
<?php header('Content-Type: application/json');
echo json_encode(['php' => PHP_VERSION, 'len' => mb_strlen('패치 영향 분석'), 'sha' => hash('sha256', 'x')]);
PHP
cat > "$W/image.php" <<'PHP'
<?php $im = imagecreatetruecolor(120, 40); imagefill($im, 0, 0, imagecolorallocate($im, 30, 60, 90));
imagestring($im, 3, 5, 12, 'PatchScope', imagecolorallocate($im, 255, 255, 255));
header('Content-Type: image/png'); imagepng($im);
PHP
cat > "$W/xml.php" <<'PHP'
<?php $d = new DOMDocument(); $d->loadXML('<r><i n="1"/><i n="2"/></r>');
$x = new DOMXPath($d); echo $x->query('//i')->length;
PHP
cat > "$W/db.php" <<'PHP'
<?php $c = pg_connect('dbname=app'); pg_query($c, "INSERT INTO orders (item, qty) VALUES ('widget', 1)");
$r = pg_fetch_row(pg_query($c, 'SELECT count(*) FROM orders')); echo $r[0];
PHP
cat > "$W/fetch.php" <<'PHP'
<?php $h = curl_init('http://127.0.0.1/app/index.php'); curl_setopt($h, CURLOPT_RETURNTRANSFER, true);
echo strlen(curl_exec($h));
PHP
cat > "$W/intl.php" <<'PHP'
<?php echo (new NumberFormatter('ko_KR', NumberFormatter::CURRENCY))->formatCurrency(1234, 'KRW');
PHP
systemctl enable --now php-fpm >/dev/null
systemctl restart php-fpm nginx

# ---- 주기 작업
cat > /etc/systemd/system/ps-web.service <<'U'
[Unit]
Description=PatchScope web traffic (php endpoints, intl.php intentionally not called)
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'for p in index image xml db fetch; do curl -fsS -o /dev/null http://127.0.0.1/app/$p.php || exit 1; done'
U
cat > /etc/systemd/system/ps-web.timer <<'U'
[Unit]
Description=PatchScope web traffic every minute
[Timer]
OnCalendar=*:*:15
AccuracySec=1s
[Install]
WantedBy=timers.target
U
cat > /usr/local/bin/ps-report.py <<'PY'
#!/usr/bin/env python3
import json, ssl, hashlib
import psycopg2
from lxml import etree
conn = psycopg2.connect(dbname="app")
cur = conn.cursor()
cur.execute("SELECT item, sum(qty) FROM orders GROUP BY item")
root = etree.Element("report")
for item, qty in cur.fetchall():
    etree.SubElement(root, "row", item=item, qty=str(qty))
xslt = etree.XSLT(etree.XML(b'<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">'
                            b'<xsl:template match="/"><n><xsl:value-of select="count(//row)"/></n></xsl:template></xsl:stylesheet>'))
out = etree.tostring(xslt(root))
print(json.dumps({"rows": out.decode(), "tls": ssl.OPENSSL_VERSION, "h": hashlib.sha256(out).hexdigest()[:8]}))
PY
chmod 0755 /usr/local/bin/ps-report.py
cat > /etc/systemd/system/ps-report.service <<'U'
[Unit]
Description=PatchScope report job (psycopg2 + lxml + ssl)
[Service]
Type=oneshot
User=apache
ExecStart=/usr/local/bin/ps-report.py
U
cat > /etc/systemd/system/ps-report.timer <<'U'
[Unit]
Description=PatchScope report every 2 minutes
[Timer]
OnCalendar=*:0/2:45
AccuracySec=1s
[Install]
WantedBy=timers.target
U
# 타이머 없음: 관측 기간에 실행되지 않는 기능
cat > /usr/local/bin/ps-export.py <<'PY'
#!/usr/bin/env python3
import bz2, lzma, zipfile, sqlite3
print("export not scheduled")
PY
chmod 0755 /usr/local/bin/ps-export.py
cat > /etc/systemd/system/ps-export.service <<'U'
[Unit]
Description=PatchScope export job (not scheduled)
[Service]
Type=oneshot
ExecStart=/usr/local/bin/ps-export.py
U
systemctl daemon-reload
systemctl enable --now ps-web.timer ps-report.timer >/dev/null
systemctl start ps-web.service ps-report.service

FPM=$(systemctl show -p MainPID --value php-fpm)
WORKER=$(pgrep -P "$FPM" | head -1)
{
  date -u +%FT%TZ
  rpm -q $(rpm -qa --qf '%{NAME}\n' | grep -E '^(php|postgresql|python3-(psycopg2|lxml)|libpng|libjpeg|freetype|libxml2|libxslt|libicu|libcurl|openssl-libs|gd)' | sort -u) 2>/dev/null
  echo "--- php-fpm worker $WORKER maps -> packages"
  grep -o '/[^ ]*\.so[^ ]*' /proc/$WORKER/maps | sort -u | xargs -r rpm -qf --qf '%{NAME}\n' 2>/dev/null | sort -u | paste -sd' '
  echo "--- endpoints"
  for p in index image xml db fetch; do printf '%s=%s ' $p "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1/app/$p.php)"; done; echo
  echo "--- report: $(sudo -u apache /usr/local/bin/ps-report.py 2>&1)"
} > "$M" 2>&1
cat "$M" | tail -8
echo "active: $(systemctl is-active nginx php-fpm postgresql ps-web.timer ps-report.timer | paste -sd' ')"
