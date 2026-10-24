#!/bin/bash
journalctl -u patchscope-server --since '-30 min' --no-pager -o cat | grep -E 'patchscope_server/[a-z_]+\.py", line|templates/[a-z_]+\.html", line|^[a-zA-Z_.]+(Error|Exception)' | tail -8
