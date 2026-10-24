#!/bin/bash
awk '$9 == 500 {print $7}' /var/log/nginx/access.log | sort | uniq -c | tail -5
journalctl -u patchscope-server --since '-60 min' --no-pager -o cat | grep -vE '^\s|^Traceback|^INFO|^\+|^\|' | grep -E 'Error|error|Exception' | sort | uniq -c | tail -6
journalctl -u patchscope-server --since '-60 min' --no-pager -o cat | grep -E 'patchscope_server/[a-z_]+\.py", line|templates/[a-z_]+\.html", line' | sort | uniq -c | tail -6
