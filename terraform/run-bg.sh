#!/usr/bin/env bash
# 긴 작업을 로그 파일로 남기며 실행:  ./run-bg.sh <name> <command...>
#   로그: terraform/.logs/<name>.log  (git 제외)
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$DIR/.logs"
NAME=$1; shift
cd "$DIR"
{ echo "### $(date '+%F %T') $*"; "$@"; echo "### EXIT $? $(date '+%F %T')"; } > "$DIR/.logs/$NAME.log" 2>&1 < /dev/null
