#!/bin/bash
# 대상 호스트: 전체 업데이트 (RELEASEVER, COMMENT 를 첫 줄 export 로 주입). 서비스 재시작·재부팅은 하지 않음.
set -uo pipefail
export DNF_NOTIFY=0
echo "kernel=$(uname -r) boot=$(cut -c1-8 /proc/sys/kernel/random/boot_id)"
ARGS=(-y -q --comment "$COMMENT")
[ -n "${RELEASEVER:-}" ] && ARGS+=(--releasever="$RELEASEVER")
N=$(dnf -q "${ARGS[@]:3}" check-update 2>/dev/null | grep -cE '^[a-zA-Z0-9]')
echo "pending=$N"
dnf "${ARGS[@]}" upgrade 2>&1 | tail -5
echo "dnf_rc=${PIPESTATUS[0]}"
echo "after pending=$(dnf -q "${ARGS[@]:3}" check-update 2>/dev/null | grep -cE '^[a-zA-Z0-9]')"
echo "installed kernels: $(rpm -q kernel | paste -sd' ')"
echo "default boot: $(grubby --default-kernel 2>/dev/null)"
echo "--- processes mapping replaced libraries (restart needed)"
for m in /proc/[0-9]*/maps; do
  grep -q '\.so.* (deleted)' "$m" 2>/dev/null || continue
  pid=$(echo "$m" | cut -d/ -f3); printf '%s\n' "$(cat /proc/$pid/comm 2>/dev/null)"
done | sort | uniq -c | sort -rn | head -15 | paste -sd' '
