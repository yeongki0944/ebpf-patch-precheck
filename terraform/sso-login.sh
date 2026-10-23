#!/usr/bin/env bash
# PatchScope PoC - AWS SSO 로그인 (device code 방식)
#
# 스크립트가 출력하는 URL 을 브라우저에서 열고 코드를 승인하면 토큰이 발급된다.
# 정적 Access Key 는 사용하지 않는다. Terraform 은 provider 의 profile 로 SSO 캐시를 사용.
#
# 사용법:
#   ./sso-login.sh                 # 로그인/확인 (Terraform 은 profile 로 동작하므로 이것으로 충분)
#   source ./sso-login.sh          # 추가로 현재 셸에 AWS_* 임시 자격증명 export
#   PROFILE=other source ./sso-login.sh

PROFILE="${PROFILE:-younggikim_poc}"
REGION="${REGION:-ap-northeast-2}"
# 기대 계정은 ~/.aws/config 의 sso_account_id 에서 읽는다 (레포에 계정 ID 를 두지 않음)
EXPECTED_ACCOUNT="${EXPECTED_ACCOUNT:-$(aws configure get sso_account_id --profile "$PROFILE" 2>/dev/null | tr -d '\r')}"

(return 0 2>/dev/null) && SOURCED=1 || SOURCED=0
_fail() { echo "[ERROR] $1" >&2; [ "$SOURCED" -eq 1 ] && return 1 || exit 1; }

# 이전 export 값이 profile 설정을 덮어쓰지 않도록 정리
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_CREDENTIAL_EXPIRATION
for v in AWS_REGION AWS_DEFAULT_REGION AWS_PROFILE; do
  [ -z "${!v:-}" ] && unset "$v"
done

_main() {
  command -v aws >/dev/null 2>&1 || { echo "[ERROR] aws cli 가 없습니다." >&2; return 1; }
  aws configure get sso_session --profile "$PROFILE" >/dev/null 2>&1 \
    || aws configure get sso_start_url --profile "$PROFILE" >/dev/null 2>&1 \
    || { echo "[ERROR] ~/.aws/config 에 SSO profile '$PROFILE' 이 없습니다." >&2; return 1; }

  echo "[INFO] profile=${PROFILE} region=${REGION}"
  if aws sts get-caller-identity --profile "$PROFILE" --region "$REGION" >/dev/null 2>&1; then
    echo "[INFO] 기존 SSO 세션이 유효합니다."
  else
    echo "[INFO] 아래 URL 을 브라우저에서 열고 표시된 코드를 승인하세요."
    aws sso login --profile "$PROFILE" --use-device-code --no-browser || { echo "[ERROR] SSO 로그인 실패" >&2; return 1; }
  fi

  local acct
  acct=$(aws sts get-caller-identity --profile "$PROFILE" --region "$REGION" --query Account --output text 2>/dev/null | tr -d '\r')
  [ -n "$acct" ] || { echo "[ERROR] 자격증명 확인 실패" >&2; return 1; }
  if [ -n "$EXPECTED_ACCOUNT" ] && [ "$acct" != "$EXPECTED_ACCOUNT" ]; then
    echo "[ERROR] 계정 불일치: 현재 ${acct}, 기대 ${EXPECTED_ACCOUNT}" >&2; return 1
  fi
  aws sts get-caller-identity --profile "$PROFILE" --region "$REGION" --output table
}

_main || _fail "로그인 절차 실패"

if [ "$SOURCED" -eq 1 ]; then
  eval "$(aws configure export-credentials --profile "$PROFILE" --format env)" \
    || { echo "[ERROR] 자격증명 export 실패" >&2; return 1; }
  export AWS_REGION="$REGION" AWS_DEFAULT_REGION="$REGION"
  echo "[INFO] 임시 자격증명을 현재 셸에 export 했습니다. 만료 시 다시 source 하세요."
fi
