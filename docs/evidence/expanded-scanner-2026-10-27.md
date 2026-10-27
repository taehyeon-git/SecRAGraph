# 확장 스캐너 평가 기록 — 2026-10-27

## 실행 조건과 입력

- 실행 코드 커밋: fc6d3e4666004b4c68b738b2b63d799fe495d34c. 두 평가 모두 이 커밋의 깨끗한 작업 트리에서 실행했습니다.
- 입력: [120건 합성 매니페스트](../../data/evaluation/scanner_cases.json), SHA-256 af99933a52a09d5e7a566a567382f2b13bce3d2047bafb1e597d7ea51d3dc403.
- 규칙 버전: 2026.10.4.
- 직접 평가: uv run --frozen python -m scripts.run_scanner_benchmark.
- 회원 API 평가: uv run --frozen python -m scripts.run_authenticated_scanner_benchmark. 격리된 Docker Compose의 FastAPI·PostgreSQL·Qdrant와 임시 회원 2명을 사용했습니다. 모델 키와 운영 API 토큰을 설정하지 않았고 자동 CWE·OSV 조회를 끈 상태로 평가했습니다. 평가용 Compose 프로젝트는 완료 뒤 정리했습니다.

120건 중 취약 라벨이 있는 사례는 64건, 라벨이 없는 사례는 56건입니다. 5건에는 라벨이 둘 이상 있습니다. 파일 종류는 Python 77, JavaScript 14, TypeScript 6, .env 11, JSON 4, YAML(.yaml) 3, YAML(.yml) 1, TOML 2, INI 2건입니다. 이 분포는 평가 범위 설명이며 실제 저장소의 언어 분포를 대표하지 않습니다.

라벨 69건은 서로 다른 **(사례, 규칙, 줄 위치)**의 정확 일치 대상입니다. 위험 함수의 호출 횟수 또는 실제 취약점 건수로 해석하지 않습니다. 구문 오류 사례 2건에서 예상된 Python 파싱 진단 2건이 나왔습니다. 라벨 없는 사례 56건 중 불완전한 Python 파일 1건은 정상 사례 오경보의 적격 분모에서 제외하여 55건입니다.

## 실측 결과

| 항목 | 로컬 직접 평가 | 회원 로그인 API 평가 |
| --- | ---: | ---: |
| 스캔 / 전체 사례 | 120 / 120 | 120 / 120 |
| TP / FP / FN | 69 / 0 / 0 | 69 / 0 / 0 |
| 정밀도 / 재현율 / F1 | 1.000 / 1.000 / 1.000 | 1.000 / 1.000 / 1.000 |
| 정상 사례 오경보 / 적격 사례 | 0 / 55 | 0 / 55 |
| 건너뜀 / 파싱 경고 | 0 / 2 | 0 / 2 |
| 예상 진단 / 예상 밖 진단 / 누락 진단 | 2 / 0 / 0 | 2 / 0 / 0 |

규칙별 TP는 JS001 13, PY001 8, PY002 8, PY003 6, PY004 6, PY005 7, PY006 6, SEC001 15건입니다. 각 규칙의 FP와 FN은 0건이었습니다. JSON 증거 파일에서 로컬 결과와 회원 API 결과의 사례별 기록, 라벨, 규칙별·전체 지표가 동일함을 확인했습니다.

회원 API에서는 각 사례를 원래 상대 경로의 단일 파일 ZIP으로 업로드했습니다. 회원 인증 업로드 120/120, 저장된 보고서와 응답 대조 120/120, finding의 상대 경로 확인 69건을 완료했습니다. 세션 없이 조회 시 401, 다른 회원의 보고서 조회 시 404, 로그아웃으로 폐기된 세션 조회 시 401이었습니다. 임시 회원은 회원 서비스로 만들었으며 스캔 대상 코드는 실행하지 않았습니다.

## 보존 증거

| 파일 | SHA-256 |
| --- | --- |
| [로컬 JSON](expanded-scanner-local-2026-10-27.json) | f20c3253fff5d52bc36cfb45ef37bb3d388e50083e90dd8457d4a6fbe4abf161 |
| [로컬 Markdown](expanded-scanner-local-2026-10-27.md) | b42171af6a2784eca95a3df9d1f85255c8e6e39f6fb2484d9c6891c46688b4f8 |
| [회원 API JSON](expanded-scanner-member-2026-10-27.json) | 9c03b4734e639d7f5c8af20756fece677895ba9c2afbab509971d92b7ba8d5bf |
| [회원 API Markdown](expanded-scanner-member-2026-10-27.md) | 7a1f485e8e166c01e1919104adb0f9fb2e37fb1a5a54851321cd3a924452834c |

원본 생성 경로는 Git 제외 대상인 build/evidence/scanner.json, build/evidence/scanner.md, build/evidence/member-scanner.json, build/evidence/member-scanner.md입니다. 보존 파일에서 비밀번호·세션 토큰·보고서 UUID·원본 사례 소스 필드는 발견되지 않았습니다.

이 점수는 **규칙 작성자가 만든 합성 회귀 사례의 정확 일치 결과**입니다. 임의 저장소의 탐지율, 실제 악용 가능성 또는 공개 서비스에서의 인증 강도를 추정하지 않습니다. 이전 [53건 회원 평가](authenticated-scanner-2026-10-27.md)와 [53건 보존 매니페스트](../../data/evaluation/history/scanner_cases_53_2026-10-27.json)는 별도 시점의 결과이며 이 표의 분모와 합치지 않습니다. [OWASP BenchmarkPython 도전](../demo.md#22-외부-스캐너-코퍼스-도전) 역시 사례와 라벨 단위가 달라 별도로 해석해야 합니다.
