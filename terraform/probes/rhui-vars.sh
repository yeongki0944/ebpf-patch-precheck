#!/bin/bash
ls /etc/dnf/vars/ 2>/dev/null; for f in /etc/dnf/vars/*; do echo "$f=$(cat "$f")"; done
grep -rl 'REGION' /etc/yum.repos.d/ | head -3
grep -m2 -E 'mirrorlist|baseurl' /etc/yum.repos.d/redhat-rhui.repo 2>/dev/null
ls /usr/lib/python3.6/site-packages/dnf-plugins/ | head -30
grep -rl "REGION" /usr/lib/python3.6/site-packages/dnf-plugins/ 2>/dev/null | head
