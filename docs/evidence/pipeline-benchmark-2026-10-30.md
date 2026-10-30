# SecRAGraph 전체 도구 벤치마크: 2026-10-30

## 무엇을 측정하는가

회원 ZIP 업로드의 실제 API 왕복을 일회용 `FastAPI + PostgreSQL + Qdrant` Compose 스택에서 측정한다. 이 경로는 로그인, Opengrep·Gitleaks·Checkov·Compose 정책 검사, LangGraph 보고서 생성, 저장과 JSON·Markdown·SARIF 재조회를 포함한다. 외부 OSV·CWE·RAG 제공자 계약은 주입한 고정 응답으로 별도 검증한다. CI는 기존 스캐너·RAG·DAST·이미지/SBOM·Git 이력 증거와 이 두 새 증거를 **같은 워크플로 실행의 분리된 트랙**으로 묶는다. 의존성 감사는 성공 여부만 기록한다. 서로 다른 정답·대상의 TP/FP/FN을 합산하지 않는다.

## 로컬 실측

이 표는 Windows Docker Desktop Linux 엔진 29.9.2에서 수행한 **개발 중 로컬 한 번의 실행**이다. 체크아웃 HEAD는 `4d9894a789489f763127463010f5dfa6eb3d18b7`이고 변경 사항이 아직 커밋되지 않아 `source_dirty=true`이다. 포트·계정·데이터 볼륨은 매번 새로 만들고 정리했다. ZIP 바이트 SHA-256은 `daa1d3c7aa2f73ed62fb1cf82cf6aaddeae756b3deba57100509e75bcd7594cb`이다.

| 항목 | 결과 |
| --- | ---: |
| 로그인·업로드·범위·JSON·Markdown·SARIF·소유권·비밀값 비노출 계약 | 10/10 |
| 실제 실행 완료 엔진 | 4/4 |
| Finding / 경고 | 10 / 0 |
| Compose 시작 | 30,750 ms |
| 회원 2명 준비 | 3,266 ms |
| 로그인 | 187 ms |
| ZIP 업로드와 검사 | 17,890 ms |
| 저장 JSON / Markdown / SARIF 조회 | 16 / 0 / 16 ms |
| Compose 정리 | 2,641 ms |

엔진 내부 기록은 Opengrep 9,141ms, Gitleaks 559ms, Checkov 8,119ms, Compose 정책 0ms였다. 이 값들은 같은 업로드의 내부 구간이라 업로드 시간과 더하지 않는다. Gitleaks가 보고한 1개 경로는 **finding이 확인된 파일**이며 전체 4개 제출 파일을 실제로 하나씩 검사했다는 영수증이 아니다. CI 러너와 Docker 캐시에 따라 시간은 크게 달라져 절대 시간 게이트로 쓰지 않는다.

`scripts/run_pipeline_contract_benchmark.py`의 별도 고정 계약은 실제 `ScanService`·LangGraph에 합성 소스와 `uv.lock`을 넣고, 제어된 OSV/CWE/RAG 포트의 호출·인용·저장 결과를 검증했다. 로컬 실행은 1/1 사례, OSV finding의 RAG 인용 있음, 20개 같은 질의에서 검색 1회였고 281ms가 걸렸다. 이 시간과 인용은 **주입한 응답**의 계약 결과이며 OSV·MITRE·Qdrant·LLM의 실시간 품질을 뜻하지 않는다.

## 측정에 따른 수정

| 확인된 문제 | 변경 전 | 변경 후 |
| --- | --- | --- |
| 같은 질의의 RAG 검색 반복 | 20개 finding에서 검색 20회, 통제된 10ms 검색 지연을 넣은 로컬 실행 219ms | 스캔 호출 내부에서 검증된 결과만 재사용해 검색 1회, 같은 조건의 로컬 실행 31ms. 모든 finding의 인용 유지 |
| OSV finding의 RAG 인용 누락 | 통제된 OSV finding 1건 중 RAG 인용 0건 | 결정론적 finding 우선순위와 20건 상한을 지키며 OSV 추가 finding도 보강해 1/1건에 인용 |
| API 스모크의 측정 범위 | 단일 Python 파일·Opengrep 결과와 JSON 조회만 확인; 단계별 시간 산출물 없음 | 혼합 ZIP의 4개 엔진, 회원 소유권, 저장 JSON·Markdown·SARIF 정합성과 단계별 시간·실행 범위를 JSON/Markdown으로 기록 |

첫 행의 시간은 **인위적인 10ms 검색 지연을 넣은 한 번의 비교**다. 실제 RAG 서비스 속도 향상률로 해석하지 않는다. 두 번째 행도 고정 포트 결과이며 외부 문서의 적합도를 평가하지 않는다. 실패·기한 초과 시 부분 근거가 보고서에 남지 않는 기존 동작을 테스트했다.

## CI 산출물과 해석

신뢰된 `main` push·주간·수동 실행에서 선행 작업이 모두 성공하면 `secragraph-pipeline-benchmark` 아티팩트가 `pipeline-benchmark.json`과 `.md`를 게시한다. 집계기는 API·스캐너·RAG·주입형 제공자·DAST·이미지/SBOM·Git 이력·의존성 감사의 **8개 트랙**을 확인한다. 원본 24개 동반 파일은 존재·크기·SHA-256을 확인하고, 각 트랙의 기본 JSON 계약을 파싱·검증한다. 소스 리비전 필드가 없는 이미지·스캐너 증거는 `unverified`로 남긴다. 동일 실행의 아티팩트를 다운로드하되 리비전 필드가 없는 자료의 개별 코드 신원을 증명한다고 주장하지 않는다.

이 벤치마크의 합성 사례 결과는 실제 저장소 탐지율이 아니다. DAST는 별도의 일회용 API를 공격하며 숫자형 SQL 주입 FN이 남아 있다. CodeQL은 별도 워크플로라 이 아티팩트에 포함되지 않는다. 외부 OWASP 도전 사례도 이 실행에서 다시 채점하지 않는다. 업로드 Compose 경로에서는 외부 OSV·CWE와 LLM 기반 RAG를 비활성화했다. 보고서가 올바르게 연결되는지와 실제 제공자가 올바른 답을 내는지는 다른 문제다.

재현: `uv run python -m scripts.compose_smoke`와 `uv run python -m scripts.run_pipeline_contract_benchmark`. 전체 묶음은 `.github/workflows/ci.yml`의 `pipeline-benchmark` 작업이 같은 실행의 선행 아티팩트를 내려받아 생성한다.
