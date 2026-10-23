#!/bin/bash
. /etc/os-release
echo "os=$ID $VERSION_ID"
command -v python3 || echo "python3 missing"
ls -l /usr/libexec/platform-python 2>/dev/null
systemctl is-active nginx redis redis6 ps-batch.timer ps-cli.timer 2>/dev/null | paste -sd' '
journalctl -u ps-batch.service -n 5 --no-pager -o cat | tail -5
rpm -q nginx redis redis6 python3 2>/dev/null | grep -v 'not installed'
