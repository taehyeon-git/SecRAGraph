# 평가와 데모

이 문서는 **현재 다중 엔진 경로**의 실행 방법과 측정 한계를 기록합니다. 서비스의 유일한 로컬 시작 명령은 [README](../README.md)의 `scripts.local_up`입니다. 평가 명령은 스캐너 검증용이며 서비스를 구동하지 않습니다.

## 1. 작성자 회귀 사례

[현재 manifest](../data/evaluation/multiengine_cases.json)는 Python·JavaScript SAST, 비밀정보, Terraform 설정의 취약·정상 파일을 함께 담습니다. 평가는 실제 `scan_path`를 호출하고 (`사례, 엔진, 규칙, 파일, 시작 줄`) 라벨을 비교합니다. 탐지 결과가 없는 정상 라벨도 채점합니다. 제출 코드는 실행하지 않습니다.

- 입력 SHA-256: `682c1c180ed5e8e20c6fc937bc919f8d3bef5da3af35328800496134f3624152`
- 도구: Opengrep 1.32.0, Gitleaks 8.30.1, Checkov 3.3.30; 잠금 파일이 없어 OSV는 이 자료에서 미채점
- 결과: 사례 14/14, 라벨 42/42 채점, 라벨 밖 finding 0건, 흐름 경로 4/4 확인
- 합계: TP 26, FP 1, FN 1; 정밀도·재현율·F1 모두 26/27 = 0.963
- 총 경과: 136,905 ms. 엔진별 누적 시간은 해당 엔진이 적격인 사례의 실행 시간 합계이며 총 경과와 정확히 같을 필요는 없습니다.

| 엔진 | TP | FP | FN | 엔진 누적 시간 |
| --- | ---: | ---: | ---: | ---: |
| Opengrep | 13 | 1 | 1 | 115,205 ms |
| Gitleaks | 1 | 0 | 0 | 7,122 ms |
| Checkov | 12 | 0 | 0 | 14,304 ms |

동봉한 벤더 SQL 패턴 규칙은 외부 입력으로 만든 f-string 쿼리 한 건을 놓쳤습니다. 별도 웹 입력 taint 규칙은 평가에서 라벨을 붙인 다른 SQL 흐름을 탐지했습니다. 개별 규칙의 분모·시간·누락과 각 실행의 파일 범위는 `build/evidence/multiengine-scanner.json` 및 `.md`에 생성됩니다. 이 사례들은 작성자가 만들었으므로 회귀 평가이지 임의 저장소의 탐지율 추정이 아닙니다. 과거 8개 자체 규칙의 120건 결과는 [역사적 증거](evidence/expanded-scanner-2026-10-27.md)로만 보존하며 현재 수치와 합치지 않습니다.

CI는 [고정 도구 이미지](../Dockerfile)를 빌드한 다음, 네트워크를 끈 읽기 전용 컨테이너에서 다음 평가를 실행합니다. Opengrep 보조 실행 파일용 `/tmp/secragraph`는 실행 가능한 임시 영역이고 제출 소스 스냅샷용 `/tmp/secragraph-snapshots`는 `noexec`입니다. 전체 Docker 옵션은 [CI 설정](../.github/workflows/ci.yml)을 참고하세요.

```text
python -m scripts.run_multiengine_benchmark --cases data/evaluation/multiengine_cases.json --staging-dir /tmp/secragraph --require-complete --require-traces
```

`--require-complete`는 미채점 엔진을, `--require-traces`는 예상한 source→sink 경로가 확인되지 않은 사례를 실패로 처리합니다. 알려진 FN을 숨기지 않기 위해 `--require-match`는 CI 게이트로 사용하지 않습니다. 호스트에서 직접 명령을 실행하려면 같은 세 도구가 PATH에 있어야 합니다.

## 2. 독립 라벨 코퍼스

공식 [OWASP BenchmarkPython](https://github.com/OWASP-Benchmark/BenchmarkPython) v0.1의 고정 리비전 `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`에서 CWE-78·89·502 사례 90개를 별도로 평가했습니다. Opengrep 1.32.0은 90/90 파일을 확인했고 **TP 27, FP 19, FN 9, TN 35**였습니다(정밀도 0.587, 재현율 0.750; 전체 번들 10,706 ms). Flask 헤더를 입력으로 모델링한 뒤 CWE-89 양성 5건 중 2건을 잡았고 정상 11건에는 해당 범위의 오경보가 없었습니다. 각 CWE와 18개 규칙의 분리 실행 시간·라벨 CSV 해시·명령은 [외부 평가 증거](evidence/multiengine-external-2026-10-27.md)에 있습니다. 공식 CSV는 CWE별 **사례 전체**의 라벨이므로 규칙별 FN은 해당 규칙이 다루지 않는 sink까지 포함할 수 있습니다. 작성자 자료의 줄 단위 점수와 합산하거나 직접 비교하지 않습니다. 외부 사례 소스는 실행하지 않았습니다.

## 3. 실제 저장소 실행 관찰

고정 리비전 `8aa828ceaff764a2e57932fb42fdf105a47c4c83`의 [Starlette](https://github.com/encode/starlette) 저장소를 한 번 측정했습니다. Opengrep은 84개 제출·49개 확인 파일에 finding 78건, `partial`이었고 Gitleaks는 94개 제출 파일에 finding 0건, `completed`였습니다. Checkov는 8개 제출·4개 확인 파일로 `partial`이었습니다. 총 경과 28,690 ms입니다. 나머지 미확인 파일 때문에 무탐을 안전 판정으로 해석할 수 없고, 78건은 사람이 판정하지 않았으므로 TP/FP가 아닙니다. [파일 범위·도구 시간·재현 절차](evidence/multiengine-external-2026-10-27.md)를 참고하세요.

## 4. 회원 API 경로

[PostgreSQL 통합 테스트](../tests/integration/api/test_member_isolation_live.py)는 회원 두 명을 생성·로그인한 뒤 ZIP을 업로드해 보고서를 저장하고, 소유자가 JSON·Markdown·SARIF을 읽을 수 있는지와 타 회원이 404를 받는지 확인합니다. 다중 엔진 finding과 실행 범위도 저장 후 대조합니다. API 동작 검증은 위 회귀 평가의 TP/FP/FN에 중복 합산하지 않습니다.

## 5. RAG와 자료 출처

`uv run --frozen python -m scripts.run_rag_evidence`는 [질문 manifest](../data/evaluation/rag_cases.json)로 지식 LangGraph의 분류·검색·인용 경로를 평가하고 `build/evidence/rag.json` 및 `rag.md`를 생성합니다. 이는 워크플로·출처 계약의 반복 시험이며 제공자 모델 답변의 사실성을 자동 채점하지 않습니다. 실제 finding과 새 모델 기반 질문이 요구하는 CWE는 공식 MITRE 항목을 검증해 필요할 때 추가합니다. PDF는 자동 탐색·다운로드하지 않으며 [별도 관리 절차](official-corpus.md)를 사용합니다.

## 6. 코드 흐름 검증

공개 저장소의 [CodeQL 워크플로](../.github/workflows/security-scan.yml)는 `security-extended`를 실행합니다. 로컬 [교차 파일 검증 기록](evidence/codeql-cross-file-smoke.md)에서 내장 `py/command-line-injection` 쿼리는 FastAPI 입력→다른 파일의 명령 실행 경로를 확인했지만 사용자 정의 허용 목록을 거친 안전 경로에도 경고를 냈습니다. [FastAPI 픽스처 쿼리](../codeql/FastApiCrossFileFlow.ql)는 여러 파일을 거치는 합성 source→sink와 명시적 차단 함수를 검증하기 위한 테스트 자료이며 제품 경고 규칙은 아닙니다. 회원의 비공개 업로드는 CodeQL 라이선스 범위 밖이므로 Opengrep의 파일 내부 taint 분석을 사용합니다.

## 7. 격리 테스트 API DAST

Docker가 실행 중인 환경에서 다음 평가 명령을 실행합니다. 이는 서비스를 시작하는 명령이 아니라 **일회용 테스트 API의 DAST 증거**를 만드는 명령입니다.

```text
uv run python -m scripts.run_dast_evidence
```

스크립트는 임의 이름의 Compose 프로젝트에서 [고정 테스트 API](../apps/dast_fixture/main.py)를 실행합니다. 테스트 API는 호스트 포트를 열지 않고 `io.secragraph.dast.disposable=true` 표시가 붙습니다. 검사기는 별도의 Docker 내부 전용 네트워크에 접속하고 OpenAPI에서 GET/HEAD/OPTIONS만 남긴 뒤 ZAP `-S` 패시브 검사 모드로 요청합니다. 임시 세션 토큰으로 `/protected`에 인증 요청이 도달한 횟수를 확인합니다. 이 API의 `/public`에는 의도적으로 `X-Content-Type-Options`가 빠져 있어 ZAP 규칙 `10021`을 확인할 수 있습니다. 검사·검증이 실패해도 Compose 프로젝트와 볼륨을 정리합니다.

성공 시 `build/evidence/dast.json`, `dast.md`, `dast.sarif`가 생성됩니다. 셋은 **같은 ScanReport**에서 렌더링됩니다. JSON에는 검사 방식과 대상 HTTP 경로, 검사 상태가 담기며, Markdown은 사람이 읽는 결과입니다. DAST SARIF는 파일 줄이 아닌 논리적 HTTP 위치를 사용하며 GitHub Code Scanning에 올리지 않습니다. 원시 ZAP 보고서와 인증 토큰은 아티팩트로 보관하지 않습니다. CI의 별도 DAST 작업은 예상 경고와 인증된 경로 접근이 없으면 실패합니다.

2026-10-28 로컬 실행에서는 ZAP 검사 실행 상태가 `completed`였고 `/public`의 `ZAP/10021` 경고 1건을 반환했습니다. 보고서 상태는 `dast_passive_only` 범위 경고를 포함해 `completed_with_warnings`였으며, SARIF에는 파일 위치 없이 논리적 HTTP 위치만 있었습니다. 이 값은 의도적으로 보안 헤더를 뺀 **합성 테스트 API 한 개**의 결과입니다.

이 시험은 응답 헤더 같은 **패시브 검사**의 실행 증거입니다. SQL 주입·명령 주입에 대한 능동 요청을 하지 않으며, 실제 운영 API의 탐지율을 의미하지 않습니다. 현재 회원 API에는 URL을 받는 DAST 엔드포인트가 없습니다. 다른 일회용 컨테이너를 검사할 때는 `security-review dast --help`의 대상 컨테이너·포트·OpenAPI 경로 옵션을 확인하세요.
