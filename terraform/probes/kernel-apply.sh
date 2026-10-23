#!/bin/bash
# 대상 호스트: 커널 설치(installonly) 후 재부팅 예약. RELEASEVER 첫 줄 주입(AL2023).
set -uo pipefail
export DNF_NOTIFY=0
echo "running=$(uname -r) boot_id=$(cat /proc/sys/kernel/random/boot_id)"
ARGS=(-y -q)
[ -n "${RELEASEVER:-}" ] && ARGS+=(--releasever="$RELEASEVER")
dnf "${ARGS[@]}" upgrade kernel 2>&1 | tail -3
echo "installed kernels: $(rpm -q kernel | paste -sd' ')"
echo "default boot: $(grubby --default-kernel 2>/dev/null)"
# SSM 응답을 먼저 돌려주고 재부팅
systemd-run --on-active=15 --unit=ps-reboot /bin/systemctl reboot >/dev/null
echo "reboot scheduled in 15s"
