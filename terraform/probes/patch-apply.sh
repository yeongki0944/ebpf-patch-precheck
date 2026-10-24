#!/bin/bash
# 대상 호스트: 운영자 패치 단계 재현 (PKGS, RELEASEVER, COMMENT 를 첫 줄 export 로 주입)
#   1) dnf upgrade --comment (작업자·계획 기록)
#   2) 일부 서비스만 재시작 (redis 는 일부러 재시작하지 않음 → 화면에 "재시작 필요"로 보여야 함)
set -uo pipefail
export DNF_NOTIFY=0
. /etc/os-release
REDIS=redis; [ "$ID" = amzn ] && REDIS=redis6
echo "before: $(rpm -q $PKGS | paste -sd' ')"
ARGS=(-y -q --comment "$COMMENT")
[ -n "${RELEASEVER:-}" ] && ARGS+=(--releasever="$RELEASEVER")
dnf "${ARGS[@]}" upgrade $PKGS 2>&1 | tail -3
echo "dnf_rc=${PIPESTATUS[0]}"
echo "after: $(rpm -q $PKGS | paste -sd' ')"
echo "dnf history last: $(dnf history list 2>/dev/null | sed -n '3p')"
echo "--- processes mapping replaced files (before restart)"
for m in /proc/[0-9]*/maps; do
  grep -q '\.so.* (deleted)' "$m" 2>/dev/null || continue
  pid=$(echo "$m" | cut -d/ -f3); printf '%s(%s) ' "$(cat /proc/$pid/comm 2>/dev/null)" "$pid"
done; echo
systemctl restart nginx php-fpm postgresql
sleep 3
echo "restarted: nginx php-fpm postgresql (left running on old libs: $REDIS, sshd, others)"
echo "--- still stale after partial restart"
for m in /proc/[0-9]*/maps; do
  grep -q '\.so.* (deleted)' "$m" 2>/dev/null || continue
  pid=$(echo "$m" | cut -d/ -f3); printf '%s ' "$(cat /proc/$pid/comm 2>/dev/null)"
done | tr ' ' '\n' | sort | uniq -c | sort -rn | head -12 | paste -sd' '
