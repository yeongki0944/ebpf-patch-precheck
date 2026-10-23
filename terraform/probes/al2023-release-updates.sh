#!/bin/bash
# AL2023: 고정 releasever 를 유지한 채, 목표 releasever 기준 업데이트 후보만 조회 (설치 안 함)
TARGET_RV="${TARGET_RV:-latest}"
echo "current=$(rpm -q --qf '%{VERSION}' system-release) target=$TARGET_RV"
dnf -q --releasever="$TARGET_RV" check-update > /tmp/cu.txt 2>/dev/null
echo "pending=$(grep -cE '^[a-zA-Z0-9]' /tmp/cu.txt)"
grep -E '^(kernel|glibc|openssl-libs|openssl|systemd|curl|libcurl|system-release)\.' /tmp/cu.txt
rm -f /tmp/cu.txt
