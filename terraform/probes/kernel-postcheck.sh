#!/bin/bash
# 대상 호스트: 재부팅 후 설계 9절 기본 검증 항목
set -uo pipefail
B=/var/lib/patchscope/baseline
echo "kernel: $(cat $B/kernel_release) -> $(uname -r)"
echo "boot_id: $(cat $B/boot_id) -> $(cat /proc/sys/kernel/random/boot_id)"
echo "uptime: $(cut -d' ' -f1 /proc/uptime)s"
echo "ssm: $(systemctl is-active amazon-ssm-agent)"
. /etc/os-release; REDIS=redis; [ "$ID" = amzn ] && REDIS=redis6
echo "required services: $(systemctl is-active nginx $REDIS ps-batch.timer ps-cli.timer | paste -sd' ')"
echo "failed units: $(systemctl --failed --no-legend | awk '{print $1}' | paste -sd' ')"
echo "kernel err (this boot): $(journalctl -k -p err -b --no-pager -q | wc -l)"
journalctl -k -p err -b --no-pager -q | head -5
echo "agent: $(systemctl is-active patchscope-agent)"
journalctl -u patchscope-agent -b --no-pager -o cat | grep -E 'status=|attached|inventory' | head -4
/opt/patchscope/bin/patchscope-agent precheck --spool /tmp/ps-pc 2>&1 | head -1
rm -rf /tmp/ps-pc
bash /dev/stdin <<'EOF' 2>/dev/null
EOF
