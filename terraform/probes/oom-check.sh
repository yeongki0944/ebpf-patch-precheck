#!/bin/bash
journalctl -k --since '-30 min' --no-pager -o cat | grep -iE 'oom|killed process|memory cgroup' | tail -5
journalctl -u patchscope-agent --since '-30 min' --no-pager -o cat | grep -E 'tasks:' | tail -4
systemctl show patchscope-agent -p MemoryMax -p MemoryCurrent -p MemoryPeak 2>/dev/null
