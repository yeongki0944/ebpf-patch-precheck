#!/bin/bash
# 대상 호스트: plan 과 같은 패키지 거래를 실제 적용 (테스트 운영자 수행 단계)
#   PKGS, RELEASEVER 를 첫 줄 export 로 주입
#   전후 동일 작업(workload-run)을 수행할 수 있도록 서비스 재시작은 명시적으로 수행
set -uo pipefail
export DNF_NOTIFY=0
echo "before: $(rpm -q $PKGS | paste -sd' ')"
ARGS=(-y -q)
[ -n "${RELEASEVER:-}" ] && ARGS+=(--releasever="$RELEASEVER")
dnf "${ARGS[@]}" upgrade $PKGS 2>&1 | tail -5
echo "dnf_rc=${PIPESTATUS[0]}"
echo "after: $(rpm -q $PKGS | paste -sd' ')"
# 삭제된(교체된) 라이브러리를 매핑 중인 프로세스 = 재시작 필요 대상
echo "--- processes still mapping replaced files (before restart)"
grep -l '(deleted)' /proc/[0-9]*/maps 2>/dev/null | while read -r m; do
  pid=$(echo "$m" | cut -d/ -f3)
  printf '%s %s %s\n' "$pid" "$(cat /proc/$pid/comm 2>/dev/null)" "$(grep -o '/[^ ]*\.so[^ ]* (deleted)' "$m" | sort -u | head -2 | paste -sd',')"
done | sort -k2 | head -30
