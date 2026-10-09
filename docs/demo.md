# 재현 가능한 데모

아래 명령은 저장소 루트에서 실행합니다. 로컬 CLI는 Python 3.11 이상과 `uv`, API 데모는 Docker Desktop Linux 엔진 또는 Linux Docker 엔진이 필요합니다. 민감한 실제 프로젝트 대신 [가짜 값만 든 예제](../examples/insecure/sample.py)를 사용하세요. 네트워크 제공자 호출은 별도 선택 사항입니다.

## 1. 모델 키 없이 정적 스캔

```powershell
uv sync --frozen --dev
uv run security-review scan examples/insecure/sample.py --format json --output build/demo.json
uv run security-review scan examples/insecure/sample.py --format markdown --output build/demo.md
uv run security-review scan examples/insecure/sample.py --format sarif --output build/demo.sarif
```

이 예제의 현재 규칙 결과는 비밀 유사 값(`SEC001`), `shell=True`(`PY002`), `eval`(`PY001`) 세 건입니다. 예제 파일은 검사 중 실행되지 않습니다. `build/demo.json`의 `redacted_evidence`에는 가려진 값만 남고, `references`가 비어 있어도 결정적 finding·수정 권고는 유효합니다. 실행마다 UUID/시각은 달라질 수 있으므로 고정 값 비교보다 규칙 ID·위치·마스킹을 확인하세요.

CI와 같은 SARIF 경로를 검증할 때는 실제 `src` 스캔을 사용합니다. [검증 스크립트](../scripts/validate_sarif.py)는 저장소의 `src/` 안에 있는 추적 파일 경로만 허용합니다. 위 예제의 `build/demo.sarif`는 이 스크립트의 입력 대상이 아닙니다.

```powershell
uv run security-review scan src --format sarif --output build/self-scan.sarif
uv run python scripts/validate_sarif.py build/self-scan.sarif
```

### 1.1 합성 스캐너 벤치마크

키·Docker·네트워크 없이 저장소 루트에서 고정된 39개 합성 사례를 재검사합니다. 평가기는 사례 파일을 실행하거나 import하지 않고 `scan_path`에 전달합니다. 매니페스트 SHA-256은 `6d77a9b45f1d9df215892969d3af6ce95f61e4ed20202fad61a24a5330bd6c2d`이며 변경 전 스캐너 기준 리비전은 `ac88e9f`입니다. [기준선의 실행 가능 커밋과 원본 출력](evidence/scanner-baseline.md)을 보존했습니다.

```powershell
uv run python -m scripts.run_scanner_benchmark
```

기본 명령은 정확한 `(사례 ID, 규칙 ID, 시작 줄)` 라벨과 검사 커버리지를 강제하고, `build/evidence/scanner.json` 및 `build/evidence/scanner.md`를 생성합니다. 이번 실행에서는 39/39 사례를 읽었고 건너뜀 0건, 파싱 경고 0건, 예상·예상 밖·누락 진단 0건이었습니다. 두 파일에는 UUID와 실행 시각을 넣지 않아 같은 리비전에서 바이트가 재현됩니다.

| 범위 | 변경 전 TP / FP / FN | 변경 전 정밀도 / 재현율 / F1 | 현재 TP / FP / FN | 현재 정밀도 / 재현율 / F1 |
| --- | ---: | ---: | ---: | ---: |
| 전체 | 9 / 6 / 9 | 0.600 (15) / 0.500 (18) / 0.545 | 18 / 0 / 0 | 1.000 (18) / 1.000 (18) / 1.000 |
| `JS001` | 0 / 0 / 3 | N/A (0) / 0.000 (3) / N/A | 3 / 0 / 0 | 1.000 (3) / 1.000 (3) / 1.000 |
| `PY001` | 3 / 2 / 0 | 0.600 (5) / 1.000 (3) / 0.750 | 3 / 0 / 0 | 1.000 (3) / 1.000 (3) / 1.000 |
| `PY002` | 2 / 2 / 1 | 0.500 (4) / 0.667 (3) / 0.571 | 3 / 0 / 0 | 1.000 (3) / 1.000 (3) / 1.000 |
| `PY003` | 1 / 2 / 2 | 0.333 (3) / 0.333 (3) / 0.333 | 3 / 0 / 0 | 1.000 (3) / 1.000 (3) / 1.000 |
| `PY004` | 0 / 0 / 3 | N/A (0) / 0.000 (3) / N/A | 3 / 0 / 0 | 1.000 (3) / 1.000 (3) / 1.000 |
| `SEC001` | 3 / 0 / 0 | 1.000 (3) / 1.000 (3) / 1.000 | 3 / 0 / 0 | 1.000 (3) / 1.000 (3) / 1.000 |

정상 사례 오경보율은 기준선 6/21 (0.286), 현재 0/21 (0.000)입니다. 이는 완전히 평가 가능한 정상 사례 중 하나 이상 예상 밖 finding이 난 비율입니다. 변경 전 `PY004`·`JS001`은 아직 구현되지 않아 TP가 0건입니다. 이 결과는 규칙 작성자가 만든 작은 합성 집합에만 해당하며, 임의 저장소의 정확도나 실제 취약점 존재를 보증하지 않습니다. 규칙별 정상 사례 분모와 불일치 목록은 생성된 Markdown에서 확인할 수 있습니다.

## 2. 루프백 API와 웹

[README 빠른 시작](../README.md#빠른-시작)의 PowerShell 비밀번호 설정·Compose 명령을 먼저 실행하고 `/health/ready`가 200인지 확인합니다. 기존 PostgreSQL 볼륨의 비밀번호가 다르면 [운영 문서](operations.md)의 회전 절차를 따르며 볼륨을 지우지 않습니다. API는 `http://127.0.0.1:8000`, Streamlit은 `http://127.0.0.1:8501`입니다.

```powershell
$scan = curl.exe -sS -F "file=@examples/insecure/sample.py;type=text/x-python" http://127.0.0.1:8000/v1/scans/file | ConvertFrom-Json
$scan.scan_id
Invoke-RestMethod "http://127.0.0.1:8000/v1/scans/$($scan.scan_id)"
curl.exe -sS "http://127.0.0.1:8000/v1/scans/$($scan.scan_id)/report?format=markdown"
```

ZIP 업로드는 `POST /v1/scans/archive`이며 보관 파일의 경로·링크·크기 제한을 검사합니다. 보고서는 `GET /v1/scans/{scan_id}`에서 JSON, `GET /v1/scans/{scan_id}/report?format=markdown|sarif`에서 렌더링된 표현으로 조회합니다. `GET /health/live`는 프로세스 생존, `GET /health/ready`는 PostgreSQL과 Qdrant 준비 상태를 확인합니다. 요청·응답 스키마는 `/docs`의 OpenAPI에서 볼 수 있습니다.

## 3. 선택적 지식 질의

동봉된 [CVE/CWE CSV](../data/samples/README.md)는 합성 데이터이므로 실제 취약점 피드로 사용하지 마세요. PostgreSQL 적재는 키 없이 실행할 수 있습니다.

```powershell
docker compose run --rm migrate /app/.venv/bin/security-review import-intelligence --cwe /app/data/samples/cwe.csv --cve /app/data/samples/cve.csv
```

RAG와 Text2SQL 답변에는 유효한 모델/임베딩 제공자 키가 필요합니다. `SECRAGRAPH_OPENAI_API_KEY`를 현재 셸의 런타임 환경 변수로 안전하게 설정하고 API를 그 설정으로 다시 시작하세요. 다음 명령은 사용자가 권리를 확인한 UTF-8 `.md`/`.markdown` 문서만 Qdrant에 수집합니다. 동봉한 `data/knowledge`는 프로젝트 고유의 예시이며 PDF 인덱싱은 지원하지 않습니다.

```powershell
docker compose up -d --force-recreate api
docker compose run --rm -e SECRAGRAPH_OPENAI_API_KEY qdrant-bootstrap /app/.venv/bin/security-review ingest-documents /app/data/knowledge
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/v1/knowledge/query -ContentType application/json -Body '{"question":"CWE 데이터는 몇 건인가요?"}'
```

분류 결과는 모델에 따라 달라질 수 있습니다. 응답의 `intent`, `sources`, `warnings`를 확인하고, RAG 인용은 해당 문서 원문과 대조하세요. 수집 데이터가 없거나 근거가 부족하면 충분한 답변이 나오지 않는 것이 정상입니다. 모델 호출은 외부 제공자 비용과 데이터 처리 정책의 영향을 받습니다.

## 4. 검증과 증거 보관

[CI 실행](https://github.com/taehyeon-git/SecRAGraph/actions/runs/37821416468)은 `v0.1.0` 태그 대상 커밋에서 테스트·품질·의존성 감사·컨테이너 빌드가 모두 통과했습니다. 같은 커밋의 [보안 셀프 스캔](https://github.com/taehyeon-git/SecRAGraph/actions/runs/37821416381)은 SARIF 생성·검증·업로드에 성공했고, [Code Scanning](https://github.com/taehyeon-git/SecRAGraph/security/code-scanning)에 결과가 반영되었습니다. 2026-10-09 확인 당시 열린 경고는 0건이지만, 이는 취약점이 없다는 보증이 아닙니다. [v0.1.0 릴리스](https://github.com/taehyeon-git/SecRAGraph/releases/tag/v0.1.0)도 공개했습니다.

2026-10-09 로컬 검증에서는 기존 볼륨을 건드리지 않고 별도 Compose 프로젝트와 포트로 PostgreSQL/Qdrant 통합 테스트 스택 및 API/웹 데모 스택을 실행했습니다. API `/health/ready`는 PostgreSQL과 Qdrant가 모두 준비됐다고 응답했고, Streamlit 헬스 엔드포인트도 HTTP 200을 반환했습니다. 합성 예제를 다시 스캔한 결과는 `PY001`, `PY002`, `SEC001` 세 건이었으며 `SEC001` 증거는 가려져 있었습니다. 전체 pytest는 602건 통과, Windows에서 심볼릭 링크 생성이 불가능해 4건 건너뜀, `security_review` 커버리지 90%였고, 통합·E2E만 별도로 실행한 47건도 통과했습니다. CI용 API 시작·준비 확인·종료 코드를 별도 로컬 포트에서 실행했을 때 실제 API 통합 테스트 2건이 통과했고 종료 뒤 포트가 해제됐습니다. `src` 셀프 스캔 SARIF는 `scripts/validate_sarif.py` 검증을 통과했습니다. 이 결과는 로컬 실행에만 해당합니다.
