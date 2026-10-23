#!/bin/bash
# PatchScope bootstrap (templatefile)
#   target  : 패치 전 상태 보존이 목적. dnf upgrade 금지, 기준 manifest 만 기록.
#   analysis: eBPF/Go 빌드 도구와 분석 서버 런타임 설치, 레포 clone.
# 시크릿(토큰·CA 키·비밀번호)은 여기 넣지 않는다. SSM 세션으로 별도 설치.
set -uo pipefail
exec > >(tee -a /var/log/patchscope-init.log) 2>&1
set -x

HOST_KEY="${host_key}"
ROLE="${role}"
OS_FAMILY="${os_family}"
REGION="${region}"
REPO_URL="${repo_url}"
STATE_DIR=/var/lib/patchscope
mkdir -p "$STATE_DIR/baseline"
hostnamectl set-hostname "patchscope-$HOST_KEY" || true

# --- SSM Agent (RHEL AMI 는 미포함일 수 있음) --------------------------------
if ! systemctl is-active --quiet amazon-ssm-agent; then
  if ! rpm -q amazon-ssm-agent >/dev/null 2>&1; then
    dnf install -y "https://s3.$REGION.amazonaws.com/amazon-ssm-$REGION/latest/linux_amd64/amazon-ssm-agent.rpm"
  fi
  systemctl enable --now amazon-ssm-agent
fi

# --- 기준 manifest (패치 전 상태 증거) ---------------------------------------
B="$STATE_DIR/baseline"
date -u +%Y-%m-%dT%H:%M:%SZ          > "$B/captured_at_utc"
cat /etc/os-release                  > "$B/os-release"
uname -r                             > "$B/kernel_release"
uname -m                             > "$B/arch"
cat /proc/sys/kernel/random/boot_id  > "$B/boot_id"
rpm -qa --qf '%%{NAME}|%%{EPOCHNUM}|%%{VERSION}|%%{RELEASE}|%%{ARCH}\n' | sort > "$B/rpm-qa.txt"
rpm -q kernel --qf '%%{NAME}-%%{EPOCHNUM}:%%{VERSION}-%%{RELEASE}.%%{ARCH}\n' > "$B/kernel-rpms.txt"
dnf repolist -v 2>/dev/null           > "$B/repolist.txt" || true
[ -f /etc/dnf/vars/releasever ] && cp /etc/dnf/vars/releasever "$B/dnf-releasever"
TOKEN=$(curl -sX PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 300')
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/ami-id > "$B/ami-id"

# BTF 존재·크기 (실제 파싱/로드 검증은 에이전트 사전 점검에서 수행)
if [ -r /sys/kernel/btf/vmlinux ]; then
  echo "present size=$(stat -c %s /sys/kernel/btf/vmlinux)" > "$B/btf"
else
  echo "absent" > "$B/btf"
fi
grep -E '^CONFIG_(DEBUG_INFO_BTF|BPF|BPF_SYSCALL|BPF_JIT|BPF_EVENTS|KPROBES|FTRACE_SYSCALLS)=' \
  "/boot/config-$(uname -r)" > "$B/kconfig-bpf.txt" 2>/dev/null || true

if [ "$ROLE" = "target" ]; then
  # 패치 전 상태 유지: 자동 업데이트 도구가 있으면 비활성화
  systemctl disable --now dnf-automatic.timer dnf-automatic-install.timer 2>/dev/null || true
  touch "$STATE_DIR/ready"
  exit 0
fi

# =========================== analysis (빌드 + 분석) ==========================
dnf install -y git make tar gzip jq clang llvm libbpf-devel bpftool \
  elfutils-libelf-devel zlib-devel kernel-headers nginx openssl \
  || { echo "base toolchain install failed" > "$STATE_DIR/error"; exit 1; }

# PostgreSQL: 저장소에 있는 최신 메이저 사용
for pg in postgresql17 postgresql16 postgresql15; do
  if dnf install -y "$pg-server" "$pg"; then echo "$pg" > "$STATE_DIR/postgres"; break; fi
done

# Python >= 3.11 (SQLAlchemy 2.1 요구)
for py in python3.12 python3.11; do
  if dnf install -y "$py" "$py-pip" "$py-devel"; then echo "$py" > "$STATE_DIR/python"; break; fi
done

# Go 1.25.x 공식 tarball, go.dev 의 sha256 으로 검증
GO_VER=go1.25.4
GO_TGZ="$GO_VER.linux-amd64.tar.gz"
GO_SHA=$(curl -fsSL "https://go.dev/dl/?mode=json&include=all" \
  | jq -r --arg f "$GO_TGZ" '.[].files[] | select(.filename==$f) | .sha256')
curl -fsSLo "/tmp/$GO_TGZ" "https://go.dev/dl/$GO_TGZ"
if [ -n "$GO_SHA" ] && echo "$GO_SHA  /tmp/$GO_TGZ" | sha256sum -c -; then
  rm -rf /usr/local/go && tar -C /usr/local -xzf "/tmp/$GO_TGZ"
  echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' > /etc/profile.d/go.sh
  echo "$GO_VER sha256=$GO_SHA" > "$STATE_DIR/go-version"
else
  echo "Go checksum verification failed" > "$STATE_DIR/error"
  exit 1
fi
rm -f "/tmp/$GO_TGZ"

# 레포 (public)
if [ ! -d /opt/patchscope/.git ]; then
  git clone "$REPO_URL" /opt/patchscope
fi

# 빌드에 필요한 vmlinux.h 는 이 호스트 BTF 에서 생성 (CO-RE)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$STATE_DIR/vmlinux.h" || true

{
  echo "clang=$(clang --version | head -1)"
  echo "bpftool=$(bpftool version | head -1)"
  echo "python=$(cat $STATE_DIR/python 2>/dev/null)"
  echo "postgres=$(rpm -q "$(cat $STATE_DIR/postgres 2>/dev/null)-server" 2>/dev/null)"
  echo "nginx=$(rpm -q nginx)"
} > "$STATE_DIR/toolchain.txt"

touch "$STATE_DIR/ready"
