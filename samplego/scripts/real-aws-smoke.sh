#!/usr/bin/env bash
#
# real-aws-smoke.sh - samplego(Go) 실 AWS 스모크 테스트
#
# 무엇을 하나:
#   실제 AWS 자격증명과 실 STS 접근이 되는 호스트에서 한 번 실행하면, samplego 서버를
#   환경변수 override 로 띄우고 클라이언트가 실 STS 를 거쳐 인증 왕복을 돌린 뒤, 세 가지
#   체크를 자동 판정해 리포트한다:
#     (1) 양성-header    : header 폼 인증 + /verify 왕복 성공
#     (2) 양성-presigned : presigned 폼 인증 + /verify 왕복 성공
#     (3) 음성-403       : allowlist 에 없는 ARN 으로 인해 arn_not_allowed(403) 거절
#   음성 케이스의 code=arn_not_allowed 는 실 STS 가 서명을 정상 검증했으나(즉 왕복이 실제로
#   일어남) 서버의 ARN 게이트에서만 막혔다는 뜻이라, 실 STS 연동이 살아있음을 함께 증명한다.
#
# 전제(이 스크립트는 실 AWS 호스트에서 사람이 직접 돌린다):
#   - 유효한 AWS 자격증명이 표준 SDK 기본 체인/EC2 IMDS 로 제공되어야 한다
#     (예: EC2 인스턴스 프로파일, IRSA, Pod Identity, 또는 로컬 구성).
#   - 서버 호스트에서 STS 엔드포인트로 아웃바운드 HTTPS(위임)가 가능해야 한다.
#   - go 와 curl 이 PATH 에 있어야 한다. caller ARN 을 자동 조회하려면 aws CLI 가 있거나
#     SMOKE_CALLER_ARN 을 직접 지정해야 한다.
#   개발/CI 컨테이너에서는 실 STS 왕복이 불가능하므로 양성/음성 판정이 통과하지 않는다.
#
# 필요 권한:
#   - sts:GetCallerIdentity (caller ARN 자동 조회에 사용. SMOKE_CALLER_ARN 을 주면 불필요).
#   - SigV4 서명에 쓰는 자격증명 자체(추가 IAM 권한 없이 서명만으로 신원 증명).
#
# 파라미터(모두 환경변수, 기본값 있음):
#   SMOKE_STS_ENDPOINT   위임/서명 대상 STS 엔드포인트   (기본 https://sts.amazonaws.com)
#   SMOKE_REGION         SigV4 서명 리전                 (기본 us-east-1)
#   SMOKE_PRESIGN_EXPIRY presigned 만료(ParseDuration)   (기본 1m)
#   SMOKE_PORT           서버 리슨 포트                  (기본 8080)
#   SMOKE_CALLER_ARN     caller ARN 직접 지정(선택)      (미지정 시 aws CLI 로 조회)
#   비표준 리전을 쓸 때는 SMOKE_STS_ENDPOINT 와 SMOKE_REGION 을 반드시 함께 정합하게 준다.
#
# 실행 예:
#   ./samplego/scripts/real-aws-smoke.sh
#   SMOKE_CALLER_ARN=arn:aws:sts::111122223333:assumed-role/my-role/i-0abc \
#     ./samplego/scripts/real-aws-smoke.sh
#
# 주의: STS_CA_FILE 은 데모(목 STS) 전용이라 이 스크립트는 절대 설정하지 않는다. 실 STS 를
#       대상으로 설정하면 지정한 CA 만 신뢰해 실 AWS TLS 가 unknown authority 로 깨진다.
#
# 종료코드: 세 체크가 모두 PASS 면 0, 하나라도 실패하면 non-zero.

set -euo pipefail

# ---- 경로 해석(cwd 의존 금지) --------------------------------------------------
# 저장소 루트는 스크립트 위치 기준으로 잡는다: <repo>/samplego/scripts/real-aws-smoke.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAMPLEGO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
SERVER_DIR="${SAMPLEGO_DIR}/server"
CLIENT_DIR="${SAMPLEGO_DIR}/client"

# ---- 파라미터 ------------------------------------------------------------------
STS_ENDPOINT="${SMOKE_STS_ENDPOINT:-https://sts.amazonaws.com}"
REGION="${SMOKE_REGION:-us-east-1}"
PRESIGN_EXPIRY="${SMOKE_PRESIGN_EXPIRY:-1m}"
PORT="${SMOKE_PORT:-8080}"
SERVER_ADDR="http://localhost:${PORT}"

# go run 은 매번 컴파일하므로 첫 기동이 느릴 수 있다. 타임아웃을 넉넉히 잡는다.
HEALTH_TIMEOUT_SECS=60   # /healthz 200 대기(초). 첫 컴파일 시간 포함.
CLIENT_TIMEOUT="90s"     # 클라이언트 실행 전체(컴파일 + 자격증명 + 서버 요청) 상한.

# 음성 케이스에 쓸, allowlist 에 절대 없을 placeholder ARN.
NOT_ALLOWED_ARN="arn:aws:iam::000000000000:role/smoke-not-allowed"

# ---- 서버 프로세스 상태/정리 ----------------------------------------------------
SERVER_PID=""
SERVER_LOG=""
# 리포트에서 참조할 로그 경로 모음(각 서버 기동마다 별도 임시 파일).
SERVER_LOGS=()

# trap 으로 간접 호출되므로 shellcheck 의 unreachable 오탐(SC2317)을 끈다.
# shellcheck disable=SC2317
cleanup() {
  stop_server
}
trap cleanup EXIT INT TERM

# start_server <allowed_arns>
# samplego 서버를 백그라운드로 띄운다. 설정은 전부 환경변수 override 로만 주입하며
# config.yaml 은 건드리지 않는다. STS_CA_FILE 은 설정하지 않는다(실 STS TLS).
start_server() {
  local allowed_arns="$1"
  SERVER_LOG="$(mktemp -t samplego-smoke-server.XXXXXX.log)"
  SERVER_LOGS+=("${SERVER_LOG}")

  # 서브셸에서 서버 디렉터리로 이동해 env 를 주입하고 백그라운드로 실행한다.
  (
    cd "${SERVER_DIR}"
    POLICY_ALLOWED_ARNS="${allowed_arns}" \
    STS_ENDPOINT_ALLOWLIST="${STS_ENDPOINT}" \
    LISTEN_ADDR=":${PORT}" \
      exec go run . >"${SERVER_LOG}" 2>&1
  ) &
  SERVER_PID="$!"
}

# stop_server
# 현재 서버 프로세스를 종료하고, 완전히 죽을 때까지 대기한다(포트 충돌 방지).
stop_server() {
  if [[ -z "${SERVER_PID}" ]]; then
    return 0
  fi
  # go run 은 자식(빌드 결과 바이너리)을 띄우므로 프로세스 그룹째 정리한다.
  kill "${SERVER_PID}" 2>/dev/null || true
  pkill -P "${SERVER_PID}" 2>/dev/null || true
  # 프로세스가 실제로 사라질 때까지 최대 10초 대기.
  local waited=0
  while kill -0 "${SERVER_PID}" 2>/dev/null; do
    sleep 1
    waited=$((waited + 1))
    if [[ "${waited}" -ge 10 ]]; then
      kill -9 "${SERVER_PID}" 2>/dev/null || true
      pkill -9 -P "${SERVER_PID}" 2>/dev/null || true
      break
    fi
  done
  SERVER_PID=""
}

# wait_health
# /healthz 가 200 이 될 때까지 폴링한다. 서버가 도중에 죽으면 로그를 덤프하고 실패한다.
# (서버는 설정 오류 시 포트를 열기 전에 non-zero 로 종료하므로, 200 이면 설정 검증 통과다.)
wait_health() {
  local waited=0
  while [[ "${waited}" -lt "${HEALTH_TIMEOUT_SECS}" ]]; do
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
      echo "  [실패] 서버 프로세스가 조기 종료됨(설정 오류 가능). 로그:" >&2
      cat "${SERVER_LOG}" >&2 || true
      return 1
    fi
    if curl -fsS -o /dev/null "${SERVER_ADDR}/healthz" 2>/dev/null; then
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done
  echo "  [실패] /healthz 가 ${HEALTH_TIMEOUT_SECS}s 안에 200 을 반환하지 않음. 로그:" >&2
  cat "${SERVER_LOG}" >&2 || true
  return 1
}

# run_client <form> [extra args...]
# 클라이언트를 실행하고 stdout/stderr/종료코드를 전역에 담는다. 실 자격증명(SDK 기본
# 체인/IMDS)을 쓰도록 --static-creds 계열은 주지 않는다.
CLIENT_OUT=""
CLIENT_ERR=""
CLIENT_RC=0
run_client() {
  local form="$1"; shift
  local out_file err_file
  out_file="$(mktemp -t samplego-smoke-client-out.XXXXXX)"
  err_file="$(mktemp -t samplego-smoke-client-err.XXXXXX)"

  CLIENT_RC=0
  (
    cd "${CLIENT_DIR}"
    go run . \
      --server-addr "${SERVER_ADDR}" \
      --sts-endpoint "${STS_ENDPOINT}" \
      --region "${REGION}" \
      --form "${form}" \
      --timeout "${CLIENT_TIMEOUT}" \
      --verify \
      "$@"
  ) >"${out_file}" 2>"${err_file}" || CLIENT_RC="$?"

  CLIENT_OUT="$(cat "${out_file}")"
  CLIENT_ERR="$(cat "${err_file}")"
  rm -f "${out_file}" "${err_file}"
}

# ---- 리포트 상태 ---------------------------------------------------------------
RESULT_HEADER="SKIP"
RESULT_PRESIGNED="SKIP"
RESULT_NEGATIVE="SKIP"
CAPTURED_ARN=""

# 양성 판정: 종료코드 0 이고 stdout 에 인증/검증 성공 마커가 모두 있으면 PASS.
judge_positive() {
  if [[ "${CLIENT_RC}" -eq 0 ]] \
    && grep -qF "발급 토큰:" <<<"${CLIENT_OUT}" \
    && grep -qF "검증 성공:" <<<"${CLIENT_OUT}"; then
    return 0
  fi
  return 1
}

# stdout 의 "  sub: <ARN>" 줄에서 STS 가 돌려준 ARN 을 캡처한다(참고용).
capture_sub_arn() {
  local line
  line="$(grep -E '^  sub: ' <<<"${CLIENT_OUT}" | head -n 1 || true)"
  if [[ -n "${line}" ]]; then
    CAPTURED_ARN="${line#  sub: }"
  fi
}

# ---- 1) 프리플라이트 -----------------------------------------------------------
echo "=== 프리플라이트 ==="

if ! command -v go >/dev/null 2>&1; then
  echo "error: go 가 PATH 에 없습니다. Go 를 설치하세요." >&2
  exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "error: curl 이 PATH 에 없습니다. curl 을 설치하세요." >&2
  exit 1
fi

# caller ARN 확정: SMOKE_CALLER_ARN 우선, 없으면 aws CLI 로 조회.
CALLER_ARN="${SMOKE_CALLER_ARN:-}"
if [[ -z "${CALLER_ARN}" ]]; then
  if command -v aws >/dev/null 2>&1; then
    CALLER_ARN="$(aws sts get-caller-identity --query Arn --output text 2>/dev/null || true)"
  fi
fi
if [[ -z "${CALLER_ARN}" || "${CALLER_ARN}" == "None" ]]; then
  echo "error: caller ARN 을 확정할 수 없습니다." >&2
  echo "       SMOKE_CALLER_ARN 을 직접 지정하거나, aws CLI 설치 + 유효한 자격증명을 갖추세요." >&2
  echo "       예: aws sts get-caller-identity --query Arn --output text" >&2
  exit 1
fi

echo "  caller ARN   : ${CALLER_ARN}"
echo "  STS endpoint : ${STS_ENDPOINT}"
echo "  region       : ${REGION}"
echo "  서버 포트    : ${PORT} (${SERVER_ADDR})"
echo

# ---- 2) 양성: allowlist 에 caller ARN 을 넣은 서버 기동 --------------------------
echo "=== 양성 서버 기동(allowlist = caller ARN) ==="
start_server "${CALLER_ARN}"
if ! wait_health; then
  echo "error: 양성 서버 기동 실패." >&2
  exit 1
fi
echo "  서버 준비됨. 로그: ${SERVER_LOG}"
echo

# ---- 3) 양성-header ------------------------------------------------------------
echo "=== [체크 1/3] 양성-header ==="
run_client header
if judge_positive; then
  RESULT_HEADER="PASS"
  capture_sub_arn
  echo "  PASS (발급 + 검증 성공)"
else
  RESULT_HEADER="FAIL"
  echo "  FAIL (rc=${CLIENT_RC})"
  [[ -n "${CLIENT_ERR}" ]] && echo "  stderr: ${CLIENT_ERR}" >&2
fi
echo

# ---- 4) 양성-presigned ---------------------------------------------------------
echo "=== [체크 2/3] 양성-presigned ==="
run_client presigned --presign-expiry "${PRESIGN_EXPIRY}"
if judge_positive; then
  RESULT_PRESIGNED="PASS"
  [[ -z "${CAPTURED_ARN}" ]] && capture_sub_arn
  echo "  PASS (발급 + 검증 성공)"
else
  RESULT_PRESIGNED="FAIL"
  echo "  FAIL (rc=${CLIENT_RC})"
  [[ -n "${CLIENT_ERR}" ]] && echo "  stderr: ${CLIENT_ERR}" >&2
fi
echo

# ---- 5) 음성-403: allowlist 를 어긋나게 한 서버로 교체 ---------------------------
echo "=== [체크 3/3] 음성-403(arn_not_allowed) ==="
stop_server   # 양성 서버를 완전히 종료한 뒤 같은 포트로 재기동.
start_server "${NOT_ALLOWED_ARN}"
if ! wait_health; then
  echo "error: 음성 서버 기동 실패." >&2
  exit 1
fi

run_client header
if [[ "${CLIENT_RC}" -ne 0 ]] \
  && grep -qF "status=403" <<<"${CLIENT_ERR}" \
  && grep -qF "code=arn_not_allowed" <<<"${CLIENT_ERR}"; then
  RESULT_NEGATIVE="PASS"
  echo "  PASS (실 STS 가 서명을 검증했고 ARN 게이트에서 403 거절)"
elif grep -qF "code=verification_failed" <<<"${CLIENT_ERR}"; then
  # 401: STS 가 서명 자체를 거절. 기대한 음성이 아니라 실 STS 연동 문제다.
  RESULT_NEGATIVE="FAIL(verification_failed)"
  echo "  FAIL: code=verification_failed(401) - 실 STS 연동 문제(서명 거절). arn_not_allowed 가 아님." >&2
  [[ -n "${CLIENT_ERR}" ]] && echo "  stderr: ${CLIENT_ERR}" >&2
else
  RESULT_NEGATIVE="FAIL"
  echo "  FAIL: 기대한 403 arn_not_allowed 미발생 (rc=${CLIENT_RC})." >&2
  [[ -n "${CLIENT_ERR}" ]] && echo "  stderr: ${CLIENT_ERR}" >&2
fi
stop_server
echo

# ---- 6) 리포트 -----------------------------------------------------------------
echo "================ 스모크 리포트 ================"
echo "  체크 1/3 양성-header    : ${RESULT_HEADER}"
echo "  체크 2/3 양성-presigned : ${RESULT_PRESIGNED}"
echo "  체크 3/3 음성-403       : ${RESULT_NEGATIVE}"
echo "  ---------------------------------------------"
echo "  caller ARN(입력)        : ${CALLER_ARN}"
[[ -n "${CAPTURED_ARN}" ]] && echo "  STS 반환 sub(양성)      : ${CAPTURED_ARN}"
echo "  STS endpoint            : ${STS_ENDPOINT}"
echo "  region                  : ${REGION}"
echo "  서버 로그 파일          :"
for log in "${SERVER_LOGS[@]}"; do
  echo "    - ${log}"
done
echo "=============================================="

if [[ "${RESULT_HEADER}" == "PASS" \
   && "${RESULT_PRESIGNED}" == "PASS" \
   && "${RESULT_NEGATIVE}" == "PASS" ]]; then
  echo "결과: 전체 PASS"
  exit 0
fi
echo "결과: 실패 있음(위 리포트 참고)" >&2
exit 1
