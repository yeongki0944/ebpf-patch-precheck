#!/bin/bash
# analysis: 장애 구간 batch 가 seq 공백 없이 들어왔는지 (호스트별 최신 세션)
q() { sudo -u patchscope psql -d patchscope -tA -F ' | ' -c "$1"; }
q "SELECT h.hostname, left(s.session_id,12), s.batch_count, s.max_seq,
          s.max_seq - s.batch_count AS missing_seq, s.incomplete_batches, cardinality(s.dropped_batch_ids),
          (SELECT count(*) FROM batches b WHERE b.session_id = s.session_id AND b.received_at - b.created_at > interval '60 s') AS delayed_batches,
          (SELECT max(b.received_at - b.created_at) FROM batches b WHERE b.session_id = s.session_id) AS max_delay
   FROM sessions s JOIN hosts h USING (host_id)
   WHERE s.session_id IN (SELECT DISTINCT ON (host_id) session_id FROM sessions ORDER BY host_id, first_window_start DESC)"
echo "--- test sessions created by duplicate test (should be removed)"
q "SELECT count(*) FROM sessions WHERE session_id LIKE 'test%'"
q "DELETE FROM sessions WHERE session_id LIKE 'test%'"
