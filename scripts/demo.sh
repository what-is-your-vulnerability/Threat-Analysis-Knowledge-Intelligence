#!/usr/bin/env bash
# 대표 데모: 규칙 도출 → 승인 → 취약 예제 검사 → 고친 예제 재검사.
# --fake: 모의 LLM으로 돌린다(비용 없음). 없으면 agent.yml의 모델을 쓴다.
set -uo pipefail
cd "$(dirname "$0")/.."

FIX=tests/fixtures/spring-members
WORK=$(mktemp -d)
CONFIG=()
FAKE_PID=""
trap '[ -n "$FAKE_PID" ] && kill "$FAKE_PID" 2>/dev/null; rm -rf "$WORK"' EXIT

if [ "${1:-}" = "--fake" ]; then
  uv run python tests/fake_llm.py serve "$FIX/fake_script.json" > "$WORK/fake.url" &
  FAKE_PID=$!
  for _ in $(seq 1 40); do [ -s "$WORK/fake.url" ] && break; sleep 0.25; done
  URL=$(cat "$WORK/fake.url")
  case "$URL" in
    http://127.0.0.1:*) ;;
    *) echo "모의 LLM을 띄우지 못함" >&2; exit 3 ;;
  esac
  export LLM_BASE_URL="$URL"
  unset OPENAI_API_KEY LLM_API_KEY
  CONFIG=(--config tests/fake.yml)
fi

COMMON=(--design "$FIX/design.md" --rules "$WORK/rules.yml")

echo "== 1. 설계문서에서 보안 규칙 후보 도출"
uv run secagent rules derive "$FIX/vulnerable" --design "$FIX/design.md" --out "$WORK/rules.yml" ${CONFIG[@]+"${CONFIG[@]}"} || exit 3

echo "== 2. 규칙 승인 (실제 사용에서는 담당자가 검토 후 승인)"
uv run secagent rules approve "$WORK/rules.yml" --all || exit 3

echo "== 3. 취약 예제 검사: 삭제 API에 관리자 확인이 빠져 있다"
uv run secagent scan "$FIX/vulnerable" --out "$WORK/before" "${COMMON[@]}" ${CONFIG[@]+"${CONFIG[@]}"}
BEFORE=$?
echo "종료 코드 $BEFORE (1이면 경고)"
[ "$BEFORE" -eq 1 ] || { echo "기대와 다름: 취약 예제는 종료 코드 1이어야 함" >&2; exit 1; }

echo "== 4. 고친 예제 재검사"
uv run secagent recheck "$FIX/fixed" --previous "$WORK/before" --out "$WORK/after" "${COMMON[@]}" ${CONFIG[@]+"${CONFIG[@]}"} | tee "$WORK/after.log"
AFTER=${PIPESTATUS[0]}
echo "종료 코드 $AFTER (0이면 통과)"
python3 - "$WORK/before/manifest.jsonl" "$WORK/after/manifest.jsonl" <<'PY'
import json, sys

rows = [json.loads(line) for path in sys.argv[1:] for line in open(path, encoding="utf-8")]
print(f"LLM 호출 {len(rows)}번, 입력 {sum(r['input_tokens'] for r in rows)} 토큰, "
      f"출력 {sum(r['output_tokens'] for r in rows)} 토큰, 호출 시간 {sum(r['seconds'] for r in rows):.0f}초")
PY
[ "$AFTER" -eq 0 ] || { echo "기대와 다름: 고친 예제는 종료 코드 0이어야 함" >&2; exit 1; }
grep -q " resolved$" "$WORK/after.log" || { echo "기대와 다름: resolved가 없음" >&2; exit 1; }
echo "resolved"
