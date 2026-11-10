# 보안 진단 Agent

설계문서와 소스코드를 받아 보안 통제가 코드에 구현됐는지 근거와 함께 판정하고, 수정 방법을 제안한다. SKALA Final Project 65번이다.

프로그램이 범위 확인, 진입점과 가드 추출, 기능 묶음, 조사 항목, 근거 확인, 판정을 맡는다. LLM은 조사 항목 하나 안에서 문제를 찾고 설명한다. AI 근거만으로는 배포를 막지 않고, 확인하지 못한 항목을 "안전"으로 표시하지 않는다.

## 설치

```bash
uv sync
cp agent.example.yml agent.yml   # 모델을 정해 적는다. agent.yml은 커밋하지 않는다.
export OPENAI_API_KEY=...        # api.openai.com으로만 보낸다. 다른 주소의 키는 LLM_API_KEY로 넘긴다.
```

모델 기본값은 없다. 역할(`onboard`, `investigate`, `review`, `fix`)마다 모델을 적지 않으면 그 역할은 호출하지 않고 실패한다. 2026-11-10 기준 사용 모델은 `gpt-6.1-terra`이고, 이 모델은 도구와 추론 강도를 함께 받지 않아 `tool_reasoning_effort: none`을 쓴다.

## 실행

```bash
scripts/demo.sh --fake        # 모의 LLM으로 대표 데모(규칙 도출 → 승인 → 검사 → 재검사)
scripts/demo.sh               # agent.yml의 모델로 같은 데모

uv run secagent rules derive TARGET --design 설계.md --out rules.yml
uv run secagent rules approve rules.yml --id R1        # 또는 --all
uv run secagent scan TARGET --design 설계.md --rules rules.yml --out runs/a
uv run secagent recheck TARGET --previous runs/a --design 설계.md --rules rules.yml --out runs/b
```

종료 코드: 0 통과, 1 경고, 2 차단, 3 실행 실패. 결과는 `--out` 폴더의 `report.html`, `report.json`, `results.sarif`, `ledger.json`이다.

로컬 API와 worker:

```bash
docker compose -f deploy/docker-compose.yml up -d --wait   # PostgreSQL만 127.0.0.1:55432
uv run secagent db-upgrade
uv run secagent api            # 127.0.0.1:8000, 인증 없음
uv run secagent worker
uv run secagent openapi > deploy/openapi.json
```

Semgrep은 `agent.yml`의 `semgrep.enabled: true`로 켠다. Docker에서 네트워크 없이 돈다.

## 시험

```bash
uv run ruff check . && uv run pytest          # 모의 LLM, 컨테이너 없이
uv run pytest -m docker                       # Semgrep 실제 컨테이너
uv run pytest -m postgres                     # docker compose로 띄운 PostgreSQL 필요
```

## 평가

```bash
uv run python eval/run.py --condition C --variant DEV-D0 --repeat 3 --experiment bc
uv run python eval/score.py bc C
uv run python eval/derive_dev_rules.py --config agent.yml   # 조건 D·E용 규칙
```

정답은 `eval/score.py`가 기존 채점기로만 읽는다. 칸별 결과 파일에는 정답 라벨이 들어 있어 커밋하지 않는다. 수치는 `eval/reports/README.md`에 있고 모두 잠정이다.

## 알려진 한계

- 진입점 자동 추출은 Java Spring만 된다. 다른 언어는 폴더 단위 묶음(partial)이나 손으로 쓴 묶음 파일(`--slices`)을 쓴다.
- 재검토는 1번이라 차단은 나오지 않는다(차단은 도구 확인 + 재검토 3번 유지일 때만).
- 위험도 점수, 배포 확률, 기준 문서 RAG, PR 연동, 의존성 점검(OSV), 탐지 규칙 생성은 아직 없다.
- 범위 밖 유형(SSRF 등)은 스캐너 규칙이 있을 때만 결과가 나오고, 없으면 리포트의 못 본 범위에 나온다.
- `rules/templates.yml`의 ASVS 항목은 도구 저장소의 JSON에서 옮겼고 ASVS 원문과 대조하지 않았다.
- DEV 수치는 공개 codefix 기반 데이터라 성능 주장에 쓰지 않는다.
