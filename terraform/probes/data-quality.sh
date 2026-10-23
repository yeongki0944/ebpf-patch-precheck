#!/bin/bash
# analysis: 수집 품질 조사 (미해결 경로, 서비스 귀속)
q() { echo "--- $1"; sudo -u patchscope psql -d patchscope -tA -F ' | ' -c "$2"; }
q "unresolved file_open by host/comm" "SELECT h.hostname, comm, count(*), sum(count) FROM records r JOIN hosts h USING(host_id) WHERE kind='file_open' AND path_status='unresolved' GROUP BY 1,2 ORDER BY 3 DESC LIMIT 12"
q "unresolved file_open sample requested paths" "SELECT comm, requested_path, dev FROM records WHERE kind='file_open' AND path_status='unresolved' ORDER BY random() LIMIT 15"
q "unresolved relative vs absolute" "SELECT left(requested_path,1)='/' AS absolute, count(*) FROM records WHERE kind='file_open' AND path_status='unresolved' GROUP BY 1"
q "init.scope records" "SELECT h.hostname, comm, kind, source, unit_source, count(*) FROM records r JOIN hosts h USING(host_id) WHERE unit='init.scope' GROUP BY 1,2,3,4,5 ORDER BY 6 DESC LIMIT 12"
q "unit_source distribution" "SELECT h.hostname, unit_source, count(DISTINCT proc_key) FROM records r JOIN hosts h USING(host_id) WHERE proc_key IS NOT NULL GROUP BY 1,2 ORDER BY 1,3 DESC"
q "cgroup mode" "SELECT 1"
stat -fc %T /sys/fs/cgroup
