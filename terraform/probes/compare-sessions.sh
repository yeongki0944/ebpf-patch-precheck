#!/bin/bash
# analysis: 호스트별 패치 전/후 세션 자동 선택 → 의존 버전 변화·실패 차이 요약 + 웹 비교 URL
q() { sudo -u patchscope psql -d patchscope -tA -F ' | ' -c "$1"; }
for H in $(q "SELECT host_id FROM hosts ORDER BY hostname"); do
  NAME=$(q "SELECT hostname FROM hosts WHERE host_id='$H'")
  # 인벤토리가 다른 가장 최근 두 세션 (전: 이전 인벤토리, 후: 최신 인벤토리)
  read -r AFTER AINV <<<"$(q "SELECT session_id, inventory_ids[1] FROM sessions WHERE host_id='$H' AND batch_count > 3 ORDER BY first_window_start DESC LIMIT 1" | tr '|' ' ')"
  BEFORE=$(q "SELECT session_id FROM sessions WHERE host_id='$H' AND batch_count > 3 AND NOT ('$AINV' = ANY(inventory_ids)) ORDER BY first_window_start DESC LIMIT 1")
  echo "=== $NAME before=${BEFORE:0:12} after=${AFTER:0:12}"
  [ -n "$BEFORE" ] && [ -n "$AFTER" ] || { echo "  (전후 세션 없음)"; continue; }
  q "WITH d AS (
       SELECT s, coalesce(unit,'-') AS unit, p AS nevra FROM (
         SELECT 'before' AS s, unit, unnest(packages) p FROM records WHERE session_id='$BEFORE' AND ownership='rpm' AND kind IN ('process','mapped_file','file_mmap','exec')
         UNION ALL
         SELECT 'after', unit, unnest(packages) FROM records WHERE session_id='$AFTER' AND ownership='rpm' AND kind IN ('process','mapped_file','file_mmap','exec')) x
       WHERE unit IN ('nginx.service','redis.service','redis6.service','ps-batch.service','ps-cli.service','sshd.service')
         AND (p LIKE 'openssl%' OR p LIKE 'glibc-0:%')
       GROUP BY 1,2,3)
     SELECT unit, string_agg(DISTINCT CASE WHEN s='before' THEN nevra END, ',') AS before,
                  string_agg(DISTINCT CASE WHEN s='after' THEN nevra END, ',') AS after
     FROM d GROUP BY unit ORDER BY unit"
  echo "  failed opens (non-ENOENT) before/after: $(q "SELECT count(*) FILTER (WHERE session_id='$BEFORE'), count(*) FILTER (WHERE session_id='$AFTER') FROM records WHERE session_id IN ('$BEFORE','$AFTER') AND kind='file_open' AND ok IS FALSE AND errno NOT IN (2)")"
  echo "  abnormal exits before/after: $(q "SELECT count(*) FILTER (WHERE session_id='$BEFORE'), count(*) FILTER (WHERE session_id='$AFTER') FROM records WHERE session_id IN ('$BEFORE','$AFTER') AND kind='exit' AND (exit_code <> 0 OR signal IS NOT NULL) AND unit IN ('nginx.service','redis.service','redis6.service','ps-batch.service','ps-cli.service')")"
  echo "  web: /compare?before=$BEFORE&after=$AFTER"
done
