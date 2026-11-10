# 보안 진단 Agent

설계문서와 소스코드를 받아 보안 통제가 코드에 구현됐는지 근거와 함께 판정하고, 수정 방법을 제안한다. SKALA Final Project 65번이다.

프로그램이 범위 확인, 진입점과 가드 추출, 기능 묶음, 조사 항목, 근거 확인, 판정을 맡는다. LLM은 조사 항목 하나 안에서 문제를 찾고 설명한다. AI 근거만으로는 배포를 막지 않고, 확인하지 못한 항목을 "안전"으로 표시하지 않는다.

## 실행 순서

검사는 LangGraph 그래프 세 개로 돈다. LLM 호출은 모두 `LlmGateway`(비밀값 가리기, 키 주소 제한, 토큰 한도, 호출 기록)를 거친다.

| 그래프 | 단계 |
|---|---|
| 검사(`core/orchestrator.py`) | `prepare`(범위 확인) → `scanner`(등록한 SAST 도구를 병렬 실행) → `structure`(색인·진입점·기능 묶음, 범위 밖 경고 제외) → `plan_cases`(조사 항목) → `run_one_case`(항목마다 반복) → `findings`(이슈·수정 제안) → `report` |
| 조사 항목(`core/case_graph.py`) | `investigate` → `check`(인용을 못 찾으면 한 번 다시 조사) → `decide`(근거 확인·재검토·판정). 호출 실패는 `fail`(검증 불충분) |
| 도구 반복(`llm/tool_loop.py`) | `ask` ↔ `act`(읽기 도구). 도구 호출 한도에 닿으면 `final`에서 그때까지 읽은 내용으로 최종 답을 받는다 |

SAST 결과는 두 가지로 LLM에 간다. 범위 안 경고는 같은 파일·같은 CWE끼리 도구를 합쳐 "실제 문제인지 확인" 항목이 되고, 그 묶음을 조사할 때 참고 자료로 붙는다(재검토에는 붙이지 않는다). 규칙·고정 질문 조사는 경고와 상관없이 모든 묶음에서 돈다.

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
uv run secagent api            # 127.0.0.1:8000, 인증 없음. Host가 127.0.0.1·localhost인 요청만 받고 상태 변경은 JSON 본문만 받는다
uv run secagent worker
uv run secagent openapi > deploy/openapi.json
```

## 스캐너 등록

SAST 도구는 `agent.yml`의 `scanners:`에 적는다. 이름을 적으면 `rules/scanners/<이름>.yml` 정의를 쓰고, 정의를 직접 적어도 된다.
도구는 Docker에서 `--network none --read-only`로 돌고, 코드는 `/src`에 읽기 전용으로 붙는다. 결과 SARIF는 `--out` 폴더의 `scanners/<이름>.sarif`에 남는다.

```yaml
scanners:
  - semgrep            # rules/scanners/semgrep.yml
```

| 필드 | 뜻 |
|---|---|
| `name` | 소문자·숫자·`-`·`_`. 결과 파일과 기록표 이름(`scanner:<이름>`) |
| `image` | Docker 이미지(태그 고정) |
| `command` | 컨테이너 안 명령. `{sarif}` 필수 |
| `rules` | 규칙 파일 glob. 정의 파일 기준(직접 적은 정의는 실행 폴더 기준) |
| `rule_arg` | 규칙 파일마다 앞에 붙일 인자(기본 `--config`) |
| `languages` | 이 언어 파일이 없으면 건너뜀(기본: 항상 실행) |
| `platform`, `pull`, `memory`, `timeout_seconds` | `--platform`, `--pull`(`missing`·`never`), 메모리(기본 4g), 시간 제한(기본 600초) |

자리표시자: `{sarif}` 결과 파일, `{rules}` 규칙 인자 목록(한 항목으로만), `{src}` 코드 폴더, `{work}` 쓰기 가능한 작업 폴더(끝나면 지움).
도구가 실패하면 기록표에 `scanner:<이름>` 못 본 범위로 남고, 다른 도구 결과로 검사는 계속된다. 금지 폴더·검사 결과 폴더·제외 폴더(`.git`, `node_modules` 등)와 심볼릭 링크 아래 파일의 경고는 버린다. Agent가 읽지 않는 확장자(`.jsp`, `build.gradle` 등)의 경고는 버리지 않고 AI 확인 없이 도구 결과로 싣는다. 금지 폴더와 검사 결과 폴더는 컨테이너 안에서 빈 폴더로 가린다.
AI는 탐지 범위(`steps/cases.py`의 `IN_SCOPE_CWES`) 안 CWE의 경고만 확인하고, 나머지는 도구 결과로만 싣는다. 경고로 만드는 확인 항목은 `max_alert_cases`(기본 50)개까지이고, 넘는 항목은 기록표에 `경고 항목 상한`으로 남기고 도구 결과로만 싣는다.
`languages`는 Agent가 아는 확장자(`steps/scope.py`의 `LANGUAGES`)로 판단하므로, 그 표에 없는 언어로만 한정한 도구는 실행되지 않는다.

### CodeQL

`rules/scanners/codeql.yml`은 Java를 빌드 없이(`--build-mode=none`) `java-security-extended`로 검사한다. 이미지는 로컬에서 빌드하고 레지스트리에서 받지 않는다(`pull: never`).

```bash
docker build --platform linux/amd64 --build-arg CODEQL_SHA256=<공식 SHA-256> \
  -t secagent-codeql:2.27.4 deploy/scanners/codeql
uv run pytest -m codeql      # 이미지가 있을 때만
```

- 라이선스: GitHub Advanced Security 없이는 OSI 오픈소스 코드와 학술 연구·시연에만 쓸 수 있다. 사내 비공개 코드에 쓰기 전에 라이선스를 확인한다.
- Apple Silicon에서는 amd64 에뮬레이션으로 돌아 느리다. 대상에 Java 파일이 없으면 건너뛴다(기록표 `scanner:codeql` deferred).
- 메모리: 컨테이너 6g, CodeQL `--ram=4096`, `--threads=4`(Docker VM 8GiB 기준). 2026-11-10 이전에 빌드한 이미지는 미리 컴파일한 쿼리를 읽지 못해 메모리 부족으로 끝나므로 다시 빌드한다.
- 빌드 없는 모드는 네트워크 없이 의존성(예: Spring)을 못 받아 추출 오류가 나면 `partial`(기록표 `not_seen`)로 남는다.

## 키와 LangSmith 설정

키는 `agent/.env`에 둔다(`.env.example`을 복사, 커밋하지 않음). 셸에 이미 있는 값이 먼저다.

```bash
cp .env.example .env    # OPENAI_API_KEY, LANGSMITH_API_KEY를 채우고
                        # SECAGENT_LANGSMITH_PROJECT=taki 줄이 있으면 LangSmith로 기록을 보낸다. 끄려면 지운다
scripts/demo.sh         # 또는 secagent scan ...
```

LangSmith는 `SECAGENT_LANGSMITH_PROJECT`(또는 `agent.yml`의 `langsmith_project`)를 적었을 때만 보낸다.
다른 프로젝트용으로 흔히 켜 두는 `LANGSMITH_PROJECT`·`LANGSMITH_TRACING`만으로는 보내지 않고, `scripts/demo.sh --fake`도 보내지 않는다.
기록 단위는 검사 그래프 → 그 단계(노드) → 조사 항목 그래프 → 도구 반복 → LLM 호출(역할·프롬프트 버전·토큰)이다.
LLM 호출에는 비밀값을 가린 뒤의 메시지와 응답이 남는다. 그래프 단계 기록은 `core/tracing.py`가 줄여 숫자·ID·질문·오류만 남기고 코드·인용·프롬프트는 개수나 타입 이름으로 바꾼다.
코드가 LangSmith 서버에도 저장되므로 비공개 평가 자료(정본, TEST)를 검사할 때는 끄고 돌린다.

## 시험

```bash
uv run ruff check . && uv run pytest          # 모의 LLM, 컨테이너 없이
uv run pytest -m docker                       # Semgrep 실제 컨테이너
uv run pytest -m postgres                     # docker compose로 띄운 PostgreSQL 필요
uv run pytest -m codeql                       # 로컬에서 빌드한 CodeQL 이미지 필요
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
