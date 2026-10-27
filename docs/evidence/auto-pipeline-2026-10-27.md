# 자동 코퍼스·OSV·단일 구동 검증 (2026-10-27)

이 기록은 이번 변경의 로컬 작업 트리에서 실행한 결과입니다. GitHub `main`의 CI 결과는 별도로 확인해야 합니다.

| 검증 | 결과 |
| --- | --- |
| 전체 테스트 | 격리된 PostgreSQL·Qdrant를 준비하고 `python -m scripts.ci_full_tests` 실행: **1,077 passed, 10 skipped**, 커버리지 **88%**. 건너뜀은 별도 런타임 프로젝트를 요구하는 컨테이너 검사 4건과 Windows 심볼릭 링크 권한이 없는 검사 6건입니다. |
| Compose 스모크 | `python -m scripts.compose_smoke`에서 API·웹·DB·Qdrant, 회원 로그인, 인증된 파일 스캔을 확인하고 해당 격리 프로젝트를 정리했습니다. |
| 공식 CWE 자동 수집 | 고정된 53개 스캐너 사례와 4개 RAG 사례의 검토된 라벨에서 **8개 CWE**를 선택했습니다. 실제 MITRE 응답으로 8/8 문서를 수집했고, SHA-256 manifest·사례별 coverage를 기록했습니다. 오프라인 재실행은 검증된 캐시를 사용했습니다. 이 결과는 원문 수집 검증이며 모델 검색·답변 품질 점수가 아닙니다. |
| 키 없는 평가 | `scripts.run_rag_evidence`: **4/4**. `scripts.run_scanner_benchmark`: **53/53**, TP=25, FP=0, FN=0. RAG 평가는 동봉 프로젝트 지침과 결정적 모델·임베딩 더블을 사용합니다. 합성 스캐너 사례는 일반 저장소의 탐지율을 뜻하지 않습니다. |
| 자동 OSV 실조회 | 별도 합성 `uv.lock`의 공개 PyPI 좌표 `jinja2 2.4.1`을 일반 스캔으로 전달했습니다. 사용자 입력 없이 좌표를 추출해 OSV.dev를 조회했고, 실행 시점에 출처 링크와 실제 CVE alias가 있는 **18개 정보 등급 finding**, 경고 0건을 확인했습니다. 권고 수는 OSV 자료의 갱신에 따라 달라질 수 있습니다. |
| 정적 검사 | `ruff format --check .`, `ruff check .`, `mypy src apps scripts/local_up.py scripts/prepare_case_corpus.py`, `bandit -q -r src apps`, `git diff --check`를 실행했습니다. |

전체 테스트용 Compose 프로젝트는 기존 로컬 데이터와 분리한 `secragraph-verify-20261027-b53e`였고, 종료 시 해당 프로젝트의 테스트 볼륨만 정리했습니다. 실제 단일 구동 명령은 이 컴퓨터에 예전 `secragraph_postgres_data` 볼륨이 있고 대응하는 `build/local/runtime.env`가 없어 의도대로 시작을 거부했습니다. 기존 볼륨과 데이터는 변경하지 않았습니다. 새 설치 경로는 시작 스크립트 단위 테스트와 격리 Compose 스모크로 검증했지만, 이 환경의 예전 볼륨에 대해 전체 명령의 최종 화면까지 실행한 결과는 아닙니다.

모델 제공자 API 키가 없어 실제 제공자 임베딩·Qdrant 색인과 LLM 답변의 품질은 검증하지 않았습니다. 자동 OSV는 지원되는 공개 `uv.lock` 및 npm 잠금 파일의 정확한 버전에만 적용됩니다. 잠금 파일이 없거나 지원하지 않는 좌표는 추정하지 않으며, 실패·부분 조회는 검사 범위 경고로 표시합니다.
