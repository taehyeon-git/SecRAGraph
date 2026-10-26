# SecRAGraph

[![CI](https://github.com/taehyeon-git/SecRAGraph/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/taehyeon-git/SecRAGraph/actions/workflows/ci.yml) · [현재 main](https://github.com/taehyeon-git/SecRAGraph/tree/main) · [초기 v0.1.0 릴리스](https://github.com/taehyeon-git/SecRAGraph/releases/tag/v0.1.0) · [Code Scanning](https://github.com/taehyeon-git/SecRAGraph/security/code-scanning)

SecRAGraph는 소스 코드를 실행하지 않고 정적 규칙으로 검사하며, LangGraph로 스캔과 보안 지식 질의를 조정하고, 선택적으로 Qdrant RAG 문서 근거와 PostgreSQL CVE/CWE Text2SQL 답변을 제공하는 백엔드·DevSecOps 포트폴리오 프로젝트입니다.

## 문제 정의

보안 검토 결과는 재현 가능한 탐지와 출처가 분명한 설명이 함께 있어야 유용합니다. 이 프로젝트는 파일·ZIP·로컬 디렉터리에서 제한된 텍스트만 읽어 규칙 기반 finding을 만들고, 소스 줄 대신 규칙별 고정 증거 문구만 담은 보고서를 JSON, Markdown, SARIF 2.1.0으로 표현합니다. API, CLI, Streamlit 데모, CI가 같은 스캔 엔진을 사용합니다.

실제 [데모 파일](examples/insecure/sample.py)을 CLI로 스캔한 JSON의 일부입니다. `scan_id`와 생성 시각은 실행마다 달라집니다.

```json
{
  "status": "completed",
  "target_name": "sample.py",
  "summary": {"total": 3},
  "findings": [{
    "rule_id": "SEC001",
    "file_path": "sample.py",
    "line_start": 5,
    "redacted_evidence": "Secret-like assignment detected: ***REDACTED***; source omitted for privacy.",
    "remediation": "Revoke exposed credentials and load replacements from an approved secret store.",
    "references": []
  }]
}
```

이 발췌는 실제 출력의 일부이며, `summary`의 나머지 필드와 다른 finding 두 건은 생략했습니다. 규칙과 한계는 [아키텍처](docs/architecture.md) 및 [데모 절차](docs/demo.md)에 있습니다.

## 핵심 아키텍처

```mermaid
flowchart LR
  CLI[Typer CLI] --> APP[ScanService]
  WEB[Streamlit] --> API[FastAPI]
  API --> APP
  APP --> SG[LangGraph scan graph]
  SG --> RULES[Deterministic scanner]
  SG -. optional evidence references .-> QD[(Qdrant)]
  APP --> REPORT[Canonical report]
  REPORT --> PG[(PostgreSQL app schema)]
  REPORT --> OUT[JSON / Markdown / SARIF]
  API --> KG[LangGraph knowledge graph]
  KG --> T2S[Guarded Text2SQL]
  T2S --> INTEL[(PostgreSQL intel.cwe / intel.cve)]
  KG --> RAG[RAG retrieval and answer]
  RAG --> QD
```

스캔 그래프는 탐지·위험 점수·수정 권고를 결정적으로 계산합니다. 설정된 경우 Qdrant가 finding에 문서 출처를 추가하지만 수정 권고 문구는 바꾸지 않습니다. PostgreSQL Text2SQL은 별도의 지식 질의 그래프에만 사용됩니다. CLI의 로컬 스캔은 모델 키나 데이터베이스 없이 동작하고, Compose의 API 스캔은 보고서 영속화를 위해 PostgreSQL을 사용합니다.

## LangGraph 워크플로

스캔 경로: `validate_input → deterministic_scan → normalize_findings → retrieve_finding_evidence → calculate_risk → build_report`. Qdrant 또는 임베딩 제공자를 사용할 수 없으면 확인된 finding은 유지하고 경고를 기록합니다. 스캔 경로는 ChatModel이나 PostgreSQL Text2SQL을 호출하지 않습니다.

지식 질의 경로: `classify_intent`가 `general_answer`, `text2sql`, `vector_search` 중 하나를 고릅니다. RAG 경로는 `vector_search → evaluate_vector_results → [rewrite_query/retry | generate_grounded_answer | stop]`로 진행하며, 근거가 없으면 부족하다고 답합니다. 일반 설명 경로에는 저장된 문서 인용이 없으므로 근거 기반 답변으로 해석하면 안 됩니다. 자세한 노드와 인터페이스는 [아키텍처](docs/architecture.md)를 보세요.

## RAG와 Text2SQL

- RAG 수집은 사용자가 실행합니다. 관리 manifest는 UTF-8 `.md`/`.markdown`과 명시적으로 지정한 PDF를 지원하며 PDF를 자동 검색하거나 다운로드하지 않습니다. PDF 원본은 manifest SHA-256으로 확인하고 추출 후 페이지·전체 문자 수를 제한하며, 원시 페이지 스트림 검사도 합니다. 압축된 PDF 데이터는 파싱 중 자원을 소모할 수 있으므로 해제된 전체 크기가 완전히 제한되는 것은 아닙니다. 임베딩 키와 Qdrant 컬렉션은 적용에 필요합니다. [동봉된 Markdown 지침](data/knowledge/secragraph-security-guidelines.md)은 프로젝트 데모 문서이고 [검증용 manifest](data/knowledge/manifest.json)에 provenance가 있습니다. [공식 PDF 코퍼스 절차](docs/official-corpus.md)는 publisher, 권리, 버전과 해시를 검토한 뒤 별도 로컬 manifest로 관리하는 방법을 설명합니다. `sync-corpus`는 기본 미리보기이며 `--apply`가 있어야 해당 관리 코퍼스만 갱신합니다.
- Text2SQL은 모델이 만든 SQL을 SQLGlot AST로 검증한 뒤 `intel.cwe`와 `intel.cve`의 제한된 `SELECT`만 읽기 전용 역할로 실행합니다. 행 수·시간·재시도가 제한됩니다. [세부 통제](docs/text2sql-security.md)를 참고하세요.
- [동봉된 CVE/CWE CSV](data/samples/README.md)는 합성 데모 데이터입니다. 실제 취약점 피드나 운영 환경의 지식 범위를 대변하지 않습니다. 외부 자료는 권리를 확인한 사용자가 직접 확보하고 수집해야 합니다.

공식 자료 한 건의 실제 수집·해시 확인·키 없는 미리보기 결과는 [NIST SSDF PDF 로컬 검증 기록](docs/evidence/official-pdf-local.md)에 남겼습니다. PDF 원본은 Git에 포함하지 않습니다.

모델 키 없이도 실제 지식 LangGraph·메모리 내 Qdrant의 RAG 경로를 재현할 수 있습니다. `uv run python -m scripts.run_rag_evidence`는 동봉한 지침과 고정 사례 4건을 평가해 `build/evidence/rag.json`, `build/evidence/rag.md`를 만들고 라벨 불일치 시 실패합니다. 2026-10-18 로컬 실행 결과는 4/4 사례 통과였으며, 직접 검색·재작성 후 검색·근거 부족 보류·가짜 인용 거부를 포함합니다. 이는 결정적 테스트 더블의 워크플로·인용 계약 결과이며 실제 LLM 품질 점수가 아닙니다. 별도의 선택 실행 `scripts.run_live_rag_evidence`는 키가 있을 때만 실제 제공자 경로를 관찰하고, 답변의 사실성은 사람 검토가 필요하다고 표시합니다. 질문, 출처 발췌, 지표 분모와 재현 절차는 [데모](docs/demo.md#2-키-없는-오프라인-rag-근거)에 있습니다.

## 빠른 시작

저장소 루트에서 Docker Desktop의 Linux 엔진(또는 Linux Docker 엔진)을 사용합니다. 아래는 Windows PowerShell 5.1/7 명령이며 DB 비밀번호 두 개를 현재 셸에만 둡니다. 회원 계정은 기동 뒤 `create-user`로 만들며 웹 UI에 공용 API 토큰은 필요하지 않습니다. 기존 `postgres_data` 볼륨이 있다면 새 `POSTGRES_PASSWORD` 대신 초기화 당시 비밀번호를 사용하세요. 계정 및 DB 운영 절차는 [운영 문서](docs/operations.md)에 있습니다.

```powershell
$adminBytes = New-Object byte[] 32
$readerBytes = New-Object byte[] 32
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
try {
    $rng.GetBytes($adminBytes)
    $rng.GetBytes($readerBytes)
} finally {
    $rng.Dispose()
}
$env:POSTGRES_PASSWORD = [BitConverter]::ToString($adminBytes).Replace('-', '')
$env:SECRAGRAPH_READER_PASSWORD = [BitConverter]::ToString($readerBytes).Replace('-', '')
docker compose config --quiet
docker compose build api web
docker compose up -d
docker compose ps -a
docker compose exec api /app/.venv/bin/security-review create-user alice
Invoke-RestMethod http://127.0.0.1:8000/health/ready
```

API와 웹 UI는 기본적으로 호스트의 `127.0.0.1:8000`, `127.0.0.1:8501`에서만 열립니다. `create-user`가 만든 계정으로 `http://127.0.0.1:8501`에 로그인하세요. 회원 세션은 API에 `Session` 인증으로 전달되고 보고서 조회는 소유자별로 제한됩니다. 선택적 `SECRAGRAPH_API_TOKEN`은 신뢰된 CLI/CI 자동화용 운영 Bearer 자격 증명입니다. 첫 빌드 시간은 환경에 따라 다릅니다. 비밀번호·토큰을 담은 `docker compose config` 전체 출력은 공유하지 마세요.

로컬 CLI는 Python 3.11 이상과 `uv`를 사용합니다. 아래 스캔에는 모델 키·PostgreSQL·Qdrant가 필요하지 않습니다.

```powershell
uv sync --frozen --dev
uv run security-review scan examples/insecure/sample.py --format markdown
uv run security-review scan examples/insecure/sample.py --format sarif --output build/sample.sarif
```

직접 API를 호출할 때는 먼저 [빠른 시작](docs/operations.md)에서 만든 회원으로 로그인합니다. `Get-Credential`은 비밀번호를 입력 기록에 남기지 않으며 로그인 응답의 세션 토큰은 현재 PowerShell 프로세스의 변수에만 둡니다. 아래 예시는 세션 인증을 사용합니다. JSON 응답의 `scan_id`로 `/v1/scans/{scan_id}` 또는 `/v1/scans/{scan_id}/report?format=markdown|sarif`를 조회할 수 있습니다. OpenAPI는 `http://127.0.0.1:8000/docs`에 있습니다.

```powershell
$credential = Get-Credential -UserName alice -Message 'SecRAGraph member login'
$secretPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($credential.Password)
try {
    $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($secretPointer)
    $loginBody = @{username = $credential.UserName; password = $plainPassword} | ConvertTo-Json -Compress
    $session = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/v1/auth/login -ContentType 'application/json' -Body $loginBody
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($secretPointer)
    Remove-Variable plainPassword, loginBody -ErrorAction SilentlyContinue
}
$authHeader = "Authorization: Session $($session.token)"
$scan = curl.exe -sS -H $authHeader -F "file=@examples/insecure/sample.py;type=text/x-python" http://127.0.0.1:8000/v1/scans/file | ConvertFrom-Json
$scan.scan_id
Invoke-RestMethod "http://127.0.0.1:8000/v1/scans/$($scan.scan_id)" -Headers @{Authorization = "Session $($session.token)"}
```

ZIP은 `POST /v1/scans/archive`에서 검증 후 처리합니다. `POST /v1/knowledge/query`는 별도 지식 기능입니다. 제공자 키, PostgreSQL 데이터, Qdrant에 수집한 문서를 준비한 뒤 호출해야 하며, 빈 Compose 시작만으로 근거 있는 답변이 생성되지는 않습니다. [운영 문서](docs/operations.md)에 샘플 데이터 적재와 Markdown 수집 명령이 있습니다.

## 키 없는 스캐너 평가

고정 합성 코퍼스는 기존 39개에서 53개 사례로 확장되었습니다. 아래 변경 전 비교는 원래 39개 매니페스트(SHA-256 `6d77a9b45f1d9df215892969d3af6ce95f61e4ed20202fad61a24a5330bd6c2d`)만 대상으로 합니다. 현재 결과는 53개 사례, manifest SHA-256 `8cca80371d91e939c01274926547074cf26d23806f6e2432738446aa968bf826`, 규칙 버전 `2026.10.4` 기준입니다.

원래 39개 코퍼스의 역사적 비교:

| 검사 | TP / FP / FN | 정밀도 (TP+FP) | 재현율 (TP+FN) | F1 | 정상 사례 오경보 / 적격 사례 | 읽은 사례 / 전체 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 변경 전 `ac88e9f` | 9 / 6 / 9 | 0.600 (15) | 0.500 (18) | 0.545 | 6/21 (0.286) | 39/39 |
| 당시 규칙 `2026.10.2` | 18 / 0 / 0 | 1.000 (18) | 1.000 (18) | 1.000 | 0/21 (0.000) | 39/39 |

현재 코퍼스 결과 (`2026.10.4`):

| TP / FP / FN | 정밀도 | 재현율 | F1 | 정상 사례 오경보 / 적격 사례 | 읽은 사례 / 전체 | manifest SHA-256 |
| ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 25 / 0 / 0 | 1.000 (25) | 1.000 (25) | 1.000 | 0/28 (0.000) | 53/53 | `8cca80371d91e939c01274926547074cf26d23806f6e2432738446aa968bf826` |

현재 실행은 53/53 사례를 읽었고 TP=25, FP=0, FN=0, 정상 사례 28건, 정밀도·재현율·F1은 각각 1.000이었습니다. 변경 전 39개 비교에서는 건너뜀 0건, Python 파싱 경고 0건, 예상·예상 밖·누락 진단 0건이었습니다. `PY004`와 `JS001`은 변경 전 규칙에 없어서 기준선의 TP가 각각 0건입니다. 두 결과 모두 규칙 작성자가 만든 작은 고정 코퍼스의 정확 일치 결과이며 임의 저장소의 탐지율이나 실제 취약점 여부를 추정하지 않습니다. [기준선 원본 기록](docs/evidence/scanner-baseline.md)과 [규칙별 수치·재현 절차](docs/demo.md#11-합성-스캐너-벤치마크)를 함께 보세요.

```powershell
uv run python -m scripts.run_scanner_benchmark
```

명령은 키·Docker·네트워크 없이 `build/evidence/scanner.json`과 `scanner.md`를 생성하며, 라벨 불일치·검사 누락·예상 밖 진단이 있으면 0이 아닌 코드로 종료합니다.

실제 분포에 가까운 별도 시험을 원하면 사용자가 직접 확보한 [OWASP Benchmark for Python](https://github.com/OWASP-Benchmark/BenchmarkPython)의 로컬 체크아웃을 커밋 SHA와 예상 결과 CSV SHA-256으로 고정해 `scripts.run_external_scanner_benchmark`에 넘길 수 있습니다. GPL 코퍼스는 이 저장소에 복사하지 않았습니다. 이 평가는 CWE-78·CWE-89·CWE-502의 **넓은 분류별 사례 단위 도전**입니다. CWE-78은 `PY002`, CWE-89는 `PY005`, CWE-502는 `PY004`/`PY006`으로 매핑하며 동적으로 조립한 `sh -c` 인수, 다른 SQL API, pickle 이외 역직렬화 sink는 미지원으로 표시합니다. 고정한 외부 도전 결과는 지원 대상 사례 90개 중 82개 스캔 완료(8개 불완전 파일 제외)로 TP=27, FP=18, FN=6, TN=31이었습니다. 이는 CWE 78/89/502의 제한된 사례 단위 결과이며 전체 OWASP Benchmark 성능이나 일반적인 코드베이스 품질을 나타내지 않습니다. [실행 방법, 고정 입력, 분모 해석](docs/demo.md)을 보세요.

## 패키지 취약점 조회

`security-review osv-query --ecosystem PyPI --package jinja2 --version 2.4.1`은 지정한 패키지와 버전을 OSV.dev에 조회합니다. 인증된 `POST /v1/vulnerabilities/query`와 웹 UI의 **Dependency CVEs** 탭도 같은 버전 범위 조회를 사용합니다. 패키지 식별자는 외부 OSV 서비스로 전송되며 빈 결과는 안전을 증명하지 않습니다. 결과의 CVE는 OSV가 실제로 반환한 CVE 기본 ID 또는 alias만 포함합니다. [OSV 조회 세부사항](docs/osv.md)을 참고하세요.

프로젝트 자신의 잠금 환경도 OSV로 감사하고 권고가 나온 라이브러리를 갱신했습니다. 실행 시점의 분모·버전·한계는 [의존성 감사 기록](docs/evidence/dependency-audit-2026-10-27.md)에 있습니다.

## 테스트와 CI

이번 변경의 로컬 전체 테스트, 격리된 Compose·회원 로그인 스모크, RAG·스캐너 평가, 정적 검사 결과는 [2026-10-27 검증 기록](docs/evidence/validation-2026-10-27.md)에 있습니다. 실제 모델 품질과 임의 저장소 스캔 정확도는 이 수치에 포함되지 않습니다.

CI의 `quality` 작업은 키 없는 RAG 증거와 오프라인 스캐너 벤치마크를 각각 실행하고, 두 평가의 JSON·Markdown 증거 파일을 검증합니다. 신뢰된 `main` push에서만 동봉된 합성 자료로 만든 네 파일을 [CI 실행 아티팩트](https://github.com/taehyeon-git/SecRAGraph/actions/workflows/ci.yml)로 14일간 게시합니다. PR 실행은 검증만 합니다. 전체 API·웹·DB·Qdrant Compose 스모크도 독립 프로젝트에서 수행하고 볼륨을 정리합니다.

별도 테스트 서비스를 시작하지 않고 아래 코드 품질 검사와 문서·CLI 테스트를 실행할 수 있습니다. [CI 정의](.github/workflows/ci.yml)는 Ruff, mypy, pytest, Bandit, 키 없는 평가 증거, 의존성 감사, 컨테이너 빌드·스모크를 구성합니다. [셀프 스캔 정의](.github/workflows/security-scan.yml)는 `src`를 SARIF로 스캔하고 [검증 스크립트](scripts/validate_sarif.py)를 실행합니다. GitHub Code Scanning 업로드는 권한이 허용되는 이벤트에서만 시도하도록 구성되어 있습니다. 과거 [v0.1.0 CI 실행](https://github.com/taehyeon-git/SecRAGraph/actions/runs/37821416468)과 [셀프 스캔](https://github.com/taehyeon-git/SecRAGraph/actions/runs/37821416381)은 이 변경 이전의 증거이며 현재 `main` 기능 검증으로 인용하지 않습니다.

```powershell
uv run ruff format --check .
uv run ruff check .
uv run mypy src apps
uv run pytest tests/unit/docs/test_documentation.py tests/e2e/test_cli.py
uv run bandit -q -r src apps
```

전체 `uv run pytest`는 통합 테스트 전용 서비스가 필요합니다. [통합 테스트 Compose](tests/compose.integration.yaml)는 PostgreSQL을 `127.0.0.1:55432`, Qdrant를 `127.0.0.1:56333`에 띄우도록 정의합니다. 일부 테스트는 `SECRAGRAPH_TEST_API_URL`의 실행 중인 API도 필요하며 기본 URL은 `http://127.0.0.1:8000`입니다. 이는 빠른 시작 Compose의 PostgreSQL/Qdrant 기본 호스트 포트 `5432`/`6333`과 별개입니다. 해당 서비스를 준비하지 않은 로컬 환경에서 전체 테스트가 통과한다고 주장하지 않습니다.

## 한계

정적 규칙은 지원되는 파일 유형과 패턴만 다룹니다. 이 프로젝트는 전문 SAST나 비밀 탐지기, 침투 시험을 대체하지 않으며, 탐지 결과가 곧 실제 악용 가능성의 증명도 아닙니다. 회원 로그인과 보고서 소유권은 로컬 배포를 위한 기능이며 공개 서비스용 속도 제한, MFA, 계정 복구를 제공하지 않습니다. OSV 결과는 명시한 패키지 버전에 한정됩니다. 공개 인터넷 서비스로 바로 배포하면 안 됩니다. 보고서의 소스 줄 증거는 제거했지만 사용자가 지정한 파일 경로·대상 이름·인용 메타데이터는 민감할 수 있고, 과거 내보낸 보고서·백업은 회수되지 않습니다. 모델 답변은 오류나 프롬프트 인젝션 영향을 받을 수 있고, 문서 근거의 품질은 사용자가 수집한 자료에 좌우됩니다. 자세한 경계와 잔여 위험은 [위협 모델](docs/threat-model.md)에 있습니다.

## 출처와 기여

이 프로젝트는 팀 교육 프로젝트 `rag-documents`와 `security-agent-langgraph`에서 배운 접근을 독립적으로 통합한 작업입니다. 팀 전체 결과를 개인 단독 성과로 표시하지 않습니다. 직접 기여한 대표 커밋, 두 팀 프로젝트와 강의 템플릿의 기여 경계, 새 SecRAGraph 구현 범위, 자료 권리는 [출처와 크레딧](docs/origins-and-credits.md)에 분리해 기록했습니다. [MIT 라이선스](LICENSE)는 새로 작성한 SecRAGraph 코드에만 적용됩니다.
