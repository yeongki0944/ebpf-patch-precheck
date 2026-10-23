#!/bin/bash
# analysis: 수신 현황 요약 (psql, patchscope 사용자 peer 인증)
q() { sudo -u patchscope psql -d patchscope -tA -F ' | ' -c "$1"; }
echo "--- agents"; q "SELECT agent_id, revoked_at IS NULL AS active, last_seen FROM agents ORDER BY 1"
echo "--- hosts"; q "SELECT hostname, os_id, os_version, kernel, capability_status, last_seen FROM hosts ORDER BY 1"
echo "--- inventories"; q "SELECT host_id, inventory_id, package_count FROM inventories"
echo "--- sessions"; q "SELECT left(session_id,12), (SELECT hostname FROM hosts h WHERE h.host_id=s.host_id), batch_count, max_seq, incomplete_batches, cardinality(dropped_batch_ids), total->>'events_received', total->>'perf_lost', ended FROM sessions s ORDER BY last_created_at DESC LIMIT 6"
echo "--- records by kind"; q "SELECT kind, count(*) FROM records GROUP BY 1 ORDER BY 2 DESC"
echo "--- service evidence (rpm)"; q "SELECT h.hostname, coalesce(unit,'-'), count(DISTINCT p) FROM records r JOIN hosts h USING(host_id), unnest(packages) p WHERE ownership='rpm' AND unit LIKE '%.service' GROUP BY 1,2 ORDER BY 1,3 DESC LIMIT 12"
echo "--- nginx access (last)"; tail -3 /var/log/nginx/access.log
echo "--- server errors"; journalctl -u patchscope-server --since '-15 min' -p warning --no-pager -o cat | tail -5
