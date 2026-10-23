#!/bin/bash
# 대상 호스트의 패치 대기 패키지 요약 (설치는 하지 않음)
echo "kernel=$(uname -r)"
dnf -q check-update > /tmp/cu.txt 2>/dev/null
echo "pending=$(grep -cE '^[a-zA-Z0-9]' /tmp/cu.txt)"
grep -E '^(kernel|glibc|openssl-libs|openssl|systemd|curl|libcurl|nginx|python3)\.' /tmp/cu.txt
rm -f /tmp/cu.txt
echo "--- repos"
dnf repolist 2>/dev/null | tail -n +2
if command -v dnf >/dev/null && [ -f /etc/amazon-linux-release ]; then
  echo "--- al2023 releasever"
  rpm -q system-release
  dnf check-release-update 2>&1 | head -5
fi
