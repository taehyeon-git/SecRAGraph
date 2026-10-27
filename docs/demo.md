# 재현 가능한 데모

아래 명령은 저장소 루트에서 실행합니다. 로컬 CLI는 Python 3.11 이상과 `uv`, API 데모는 Docker Desktop Linux 엔진 또는 Linux Docker 엔진이 필요합니다. 민감한 실제 프로젝트 대신 [가짜 값만 든 예제](../examples/insecure/sample.py)를 사용하세요. 네트워크 제공자 호출은 별도 선택 사항입니다.

## 1. 모델 키 없이 정적 스캔

```powershell
uv sync --frozen --dev
uv run security-review scan examples/insecure/sample.py --format json --output build/demo.json
uv run security-review scan examples/insecure/sample.py --format markdown --output build/demo.md
uv run security-review scan examples/insecure/sample.py --format sarif --output build/demo.sarif
```

이 예제의 현재 규칙 결과는 비밀 유사 값(`SEC001`), `shell=True`(`PY002`), `eval`(`PY001`) 세 건입니다. 예제 파일은 검사 중 실행되지 않습니다. `redacted_evidence`는 소스 줄에서 일부를 가린 문자열이 아니라 규칙별 고정 문구입니다. 비밀의 원문·주변 텍스트를 보고서에 복사하지 않습니다. `references`가 비어 있어도 결정적 finding·수정 권고는 유효합니다. 실행마다 UUID/시각은 달라질 수 있으므로 규칙 ID·위치·고정 증거 문구를 확인하세요.

CI와 같은 SARIF 경로를 검증할 때는 실제 `src` 스캔을 사용합니다. [검증 스크립트](../scripts/validate_sarif.py)는 저장소의 `src/` 안에 있는 추적 파일 경로만 허용합니다. 위 예제의 `build/demo.sarif`는 이 스크립트의 입력 대상이 아닙니다.

```powershell
uv run security-review scan src --format sarif --output build/self-scan.sarif
uv run python scripts/validate_sarif.py build/self-scan.sarif
```

### 1.1 합성 스캐너 벤치마크

키·Docker·네트워크 없이 저장소 루트에서 고정 합성 사례를 재검사합니다. 평가기는 사례 파일을 실행하거나 import하지 않고 `scan_path`에 전달합니다. 변경 전 비교는 원래 39개 매니페스트(SHA-256 `6d77a9b45f1d9df215892969d3af6ce95f61e4ed20202fad61a24a5330bd6c2d`)와 기준 리비전 `ac88e9f`를 사용합니다. 현재 코퍼스는 53개이며 manifest SHA-256은 `8cca80371d91e939c01274926547074cf26d23806f6e2432738446aa968bf826`, 규칙 버전은 `2026.10.4`입니다. [기준선의 실행 가능 커밋과 원본 출력](evidence/scanner-baseline.md)을 보존했습니다.

```powershell
uv run python -m scripts.run_scanner_benchmark
```

기본 명령은 정확한 `(사례 ID, 규칙 ID, 시작 줄)` 라벨과 검사 커버리지를 강제하고, `build/evidence/scanner.json` 및 `build/evidence/scanner.md`를 생성합니다. 현재 실행은 53/53 사례를 읽었고 TP=25, FP=0, FN=0, 정상 사례 28건이었습니다(정밀도·재현율·F1 각 1.000). 증거 파일에는 UUID와 실행 시각을 넣지 않아 같은 리비전에서 바이트가 재현됩니다.

원래 39개 코퍼스의 역사적 변경 전후 비교:

| 범위 | 변경 전 TP / FP / FN | 변경 전 정밀도 / 재현율 / F1 | 당시 TP / FP / FN | 당시 정밀도 / 재현율 / F1 |
| --- | ---: | ---: | ---: | ---: |
| 전체 | 9 / 6 / 9 | 0.600 (15) / 0.500 (18) / 0.545 | 18 / 0 / 0 | 1.000 (18) / 1.000 (18) / 1.000 |
| `JS001` | 0 / 0 / 3 | N/A (0) / 0.000 (3) / N/A | 3 / 0 / 0 | 1.000 (3) / 1.000 (3) / 1.000 |
| `PY001` | 3 / 2 / 0 | 0.600 (5) / 1.000 (3) / 0.750 | 3 / 0 / 0 | 1.000 (3) / 1.000 (3) / 1.000 |
| `PY002` | 2 / 2 / 1 | 0.500 (4) / 0.667 (3) / 0.571 | 3 / 0 / 0 | 1.000 (3) / 1.000 (3) / 1.000 |
| `PY003` | 1 / 2 / 2 | 0.333 (3) / 0.333 (3) / 0.333 | 3 / 0 / 0 | 1.000 (3) / 1.000 (3) / 1.000 |
| `PY004` | 0 / 0 / 3 | N/A (0) / 0.000 (3) / N/A | 3 / 0 / 0 | 1.000 (3) / 1.000 (3) / 1.000 |
| `SEC001` | 3 / 0 / 0 | 1.000 (3) / 1.000 (3) / 1.000 | 3 / 0 / 0 | 1.000 (3) / 1.000 (3) / 1.000 |

현재 코퍼스 (`2026.10.4`) 결과:

| TP / FP / FN | 정밀도 / 재현율 / F1 | 정상 사례 오경보 / 적격 사례 | 읽은 사례 / 전체 | manifest SHA-256 |
| ---: | ---: | ---: | ---: | --- |
| 25 / 0 / 0 | 1.000 / 1.000 / 1.000 | 0/28 (0.000) | 53/53 | `8cca80371d91e939c01274926547074cf26d23806f6e2432738446aa968bf826` |

위 표와 정상 사례 오경보율은 원래 39개 코퍼스에 대한 역사적 비교입니다(기준선 6/21, 현재 당시 규칙 0/21). 최신 53개 실행은 정상 사례 28개 모두에서 finding이 없었습니다. 오경보율은 완전히 평가 가능한 정상 사례 중 하나 이상 예상 밖 finding이 난 비율입니다. 변경 전 `PY004`·`JS001`은 아직 구현되지 않아 TP가 0건입니다. 모든 수치는 규칙 작성자가 만든 작은 합성 집합에만 해당하며, 임의 저장소의 정확도나 실제 취약점 존재를 보증하지 않습니다. 규칙별 정상 사례 분모와 불일치 목록은 생성된 Markdown에서 확인할 수 있습니다.

## 2. 키 없는 오프라인 RAG 근거

다음 명령은 동봉한 [보안 지침](../data/knowledge/secragraph-security-guidelines.md)을 기존 Markdown 청커로 읽고, 메모리 내 Qdrant와 실제 지식 LangGraph를 실행합니다. Docker·PostgreSQL·모델 키는 필요하지 않습니다. `build/evidence/rag.json`과 `build/evidence/rag.md`는 생성 파일이므로 Git에서 무시됩니다.

```powershell
uv run python -m scripts.run_rag_evidence
```

2026-10-09 이 명령의 고정 사례 4건은 모두 기대 경로와 결과에 일치했습니다(`RAG evidence: PASS (4/4 cases)`). 예를 들어 실제 질문 **“How do parameterized queries bind application values safely?”**에 대해 `classify_intent → vector_search → evaluate_vector_results → generate_grounded_answer`가 실행됐습니다. `Injection-resistant data access` 섹션의 검색 조각 `92f1598e-aff4-56a7-b054-b9300740eedf`를 인용했으며, 증거의 짧은 원문 발췌는 “Use parameterized queries whenever application data influences a database statement.”로 시작합니다. 이 ID는 답변의 `[source:92f1598e-aff4-56a7-b054-b9300740eedf]`와 연결됩니다. Markdown에는 인용된 조각의 최대 240자 발췌만 표시하고, 검색만 된 다른 조각은 제목·섹션·점수 같은 메타데이터로만 표시합니다.

근거가 없는 질문 **“How do we tune asteroid orbit telemetry for lunar mining?”**은 두 번 검색한 뒤 `insufficient_evidence` 경고와 함께 보류했고, 인용·출처를 내지 않았습니다. 별도 사례에서는 결정적 응답 어댑터에 `adapter_fault=forged_citation`을 주입해 가짜 ID를 만들고, 그래프가 `invalid_source_citation`으로 거부하는지 확인했습니다. 이 결함 주입은 기대 라벨과 독립적이므로 실패를 정상 답변으로 바꾸지 않습니다.

고정 사례의 집계는 경로 일치 4/4, 관련 섹션 검색 hit@k 3/3(근거 부족 사례 1건 미적용), 인용 섹션 정합성·인용 ID 유효성·반환 `sources` 정합성 각각 2/2(정상 답변 2건만 적용, 나머지 2건 미적용), 근거 부족 보류 1/1(나머지 3건 미적용)입니다. 분모는 해당 검사가 적용되는 사례 수이며, 외부 질문 분포의 정확도나 LLM 답변 품질이 아닙니다. JSON과 Markdown의 `manifest_sha256`은 매니페스트 바이트, `corpus_sha256`/`corpus_digest_kind=indexed-chunks-v1`은 원본 파일 바이트가 아닌 **실제로 인덱싱한 정규화 chunk 레코드**, `embedding_algorithm_version`은 토큰 해시 구현 버전을 식별합니다. `git_revision`, `git_dirty`, `source_fingerprint`는 실행 코드 상태 확인용입니다.

이 어댑터는 검색 결과에서 첫 문장을 골라 인용하는 결정적 테스트 더블이며 실제 모델 호출이나 의미 임베딩 성능을 측정하지 않습니다. 실제 제공자 경로와 자료 전송의 신뢰 경계는 [위협 모델](threat-model.md)에 있습니다.

### 2.1 선택적 실제 제공자 관찰

실제 모델·임베딩 동작을 보고 싶다면 본인이 제공자 키를 설정한 뒤에만 다음 명령을 실행합니다. CI나 기본 데모는 이를 실행하지 않습니다. 지침 문서와 평가 질문이 외부 제공자로 전송되고 비용이 발생할 수 있습니다. 출력은 `build/evidence/rag-live.json`이며 원문 답변 대신 해시, 모델 ID, 경로·검색·인용·보류 판정의 분자/분모, 지연 시간, 실패 건수를 기록합니다. 사실성은 자동 채점하지 않고 사람의 원문 대조가 필요하다고 명시합니다. 키가 없으면 제공자를 만들기 전에 중단합니다.

```powershell
# First set SECRAGRAPH_OPENAI_API_KEY in this session using your own secret manager.
uv run python -m scripts.run_live_rag_evidence
Remove-Item Env:SECRAGRAPH_OPENAI_API_KEY
```

### 2.2 외부 스캐너 코퍼스 도전

[OWASP Benchmark for Python](https://github.com/OWASP-Benchmark/BenchmarkPython)은 이 저장소에 포함하지 않았습니다. 사용자가 별도 체크아웃을 확보하고 해당 라이선스를 확인한 뒤, 정확한 커밋 SHA와 `expectedresults-0.1.csv`의 SHA-256을 고정해 실행합니다. 예를 들어 로컬 체크아웃을 `C:\benchmarks\BenchmarkPython`에 두었다면 다음과 같습니다. 자리 표시자는 직접 확인한 실제 값으로 바꿔야 합니다.

```powershell
$benchmarkRoot = 'C:\benchmarks\BenchmarkPython'
$revision = (git -C $benchmarkRoot rev-parse HEAD).Trim()
$expectedHash = (Get-FileHash -Algorithm SHA256 (Join-Path $benchmarkRoot 'expectedresults-0.1.csv')).Hash.ToLowerInvariant()
uv run python -m scripts.run_external_scanner_benchmark --root $benchmarkRoot --revision $revision --expected-sha256 $expectedHash
```

이 도구는 대상 Python 코드를 실행/import하지 않고 읽기만 합니다. CWE-78→`PY002`, CWE-89→`PY005`, CWE-502→`PY004`/`PY006`의 **넓은 CWE 단위 사례 평가**이며 해당 CWE의 모든 sink를 탐지한다는 뜻이 아닙니다. case는 기대 규칙군과 실제 일치 규칙 ID를 기록하고 관련 없는 규칙 finding은 매치로 세지 않습니다. TP/FP/FN/TN과 전체 라벨·지원 범위·누락/중복/파싱 실패 분모를 분리합니다. 동적으로 조립한 `sh -c` 인수, 다른 SQL API 및 pickle 이외 역직렬화 API는 미지원 sink이며, CWE 단위 범위가 낮은 재현율로 이어질 수 있습니다. 누락·불완전 사례가 있으면 0이 아닌 종료 코드를 반환합니다.

2026-10-27 로컬 도전 실행은 BenchmarkPython revision `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`와 라벨 CSV SHA-256 `0c5ae0f9a8cdcb49549c459a25651cc058c7b17d621fc064ade2bd942dad80b8`을 검증했습니다. 총 1,230개 라벨 중 지원 CWE 78/89/502 사례 90개, 스캔 완료 82개(불완전 Python 사례 8개)는 TP=27, FP=18, FN=6, TN=31이었습니다(precision 27/45=0.600, recall 27/33=0.818). 좁은 local def-use 추적으로 전체 TP가 22에서 27로 늘고 FN이 11에서 6으로 줄었습니다. 나머지 1,140개 지원 밖 CWE 사례는 점수에서 제외했습니다: CWE-22 168, CWE-328 151, CWE-330 326, CWE-501 37, CWE-601 34, CWE-611 28, CWE-614 39, CWE-643 186, CWE-79 89, CWE-90 29, CWE-94 53. 이는 범위가 제한된 도전 결과이며 전체 BenchmarkPython 성능을 나타내지 않습니다.

오류 유형을 확인하기 위해 사례 소스는 실행하지 않고 AST 구조만 읽었습니다. 예를 들어 `BenchmarkTest00349`는 benign 라벨이어도 `pickle.loads` 호출이 있어 입력 신뢰도를 구별하지 못하는 `PY006` 오경보였고, `BenchmarkTest00350`은 benign 라벨의 `subprocess.run(shell=True)`가 `PY002` 오경보가 됐습니다. `BenchmarkTest00099`처럼 SQL f-string을 변수에 저장한 뒤 `execute`에 전달하는 사례는 좁은 local def-use 추적으로 잡혔습니다. 남은 `BenchmarkTest00165` FN은 목록에 명령 인수를 나중에 추가하는 방식이어서 현재 PY002 규칙의 범위 밖입니다. 리터럴 `sh -c`·`cmd /c` 목록에 동적 명령 문자열이 직접 들어간 경우는 탐지합니다. 점수는 넓은 CWE 범위와 8개 불완전 파일의 한계를 포함하며 일반적인 재현율을 뜻하지 않습니다.

## 3. 로컬 회원 로그인과 루프백 API

[README 시작 및 구동](../README.md#시작-및-구동)의 단일 명령을 실행해 회원을 만드세요. 웹 UI(`http://127.0.0.1:8501`)가 기본 클라이언트이며, 직접 API 호출은 다음처럼 회원 Session을 사용합니다. `Get-Credential`은 비밀번호를 입력 기록에 남기지 않습니다. 기존 PostgreSQL 볼륨의 비밀번호 파일이 없으면 [운영 문서](operations.md)의 복구 절차를 따르며 볼륨을 지우지 않습니다.

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
$headers = @{Authorization = "Session $($session.token)"}
$scan = curl.exe -sS -H $authHeader -F "file=@examples/insecure/sample.py;type=text/x-python" http://127.0.0.1:8000/v1/scans/file | ConvertFrom-Json
$scan.scan_id
Invoke-RestMethod "http://127.0.0.1:8000/v1/scans/$($scan.scan_id)" -Headers $headers
curl.exe -sS -H $authHeader "http://127.0.0.1:8000/v1/scans/$($scan.scan_id)/report?format=markdown"
```

ZIP 업로드는 `POST /v1/scans/archive`이며 보관 파일의 경로·링크·크기 제한을 검사합니다. 보고서는 `GET /v1/scans/{scan_id}`에서 JSON, `GET /v1/scans/{scan_id}/report?format=markdown|sarif`에서 렌더링된 표현으로 조회하며 회원은 자신의 보고서만 볼 수 있습니다. Session 또는 설정된 운영 Bearer 자격 증명 없이 보호된 `/v1/*` 경로를 호출하면 401입니다. `GET /health/live`는 프로세스 생존, `GET /health/ready`는 PostgreSQL과 Qdrant 준비 상태를 확인합니다. 요청·응답 스키마는 `/docs`의 OpenAPI에서 볼 수 있습니다. 회원 로그인·세션 동작은 [회원 문서](membership.md)를 참고하세요.

## 4. 선택적 지식 질의

동봉된 [CVE/CWE CSV](../data/samples/README.md)는 합성 데이터입니다. [단일 시작 명령](../README.md#시작-및-구동)이 새 데이터베이스에만 이를 적재하므로 실제 취약점 피드로 해석하지 마세요.

실제 RAG와 Text2SQL 답변에는 유효한 모델·임베딩 제공자 키가 필요합니다. 키를 현재 셸의 `SECRAGRAPH_OPENAI_API_KEY`에 안전하게 설정한 뒤 같은 단일 시작 명령을 다시 실행하면, 공식 수집 또는 검증된 캐시가 있을 때 사례별 CWE 코퍼스를 전용 Qdrant 컬렉션에 동기화합니다. 키가 없거나 검증된 공식 코퍼스가 없으면 앞의 키 없는 평가 증거만 생성됩니다. 별도 PDF를 추가할 때는 [공식 PDF 코퍼스 절차](official-corpus.md)를 따르세요.

앞 절의 회원 로그인으로 얻은 `$headers`를 이용해 질의합니다.

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/v1/knowledge/query -Headers $headers -ContentType application/json -Body '{"question":"CWE 데이터는 몇 건인가요?"}'
```

분류 결과는 모델에 따라 달라질 수 있습니다. 응답의 `intent`, `sources`, `warnings`를 확인하고 RAG 인용을 원문과 대조하세요. 근거가 부족하면 보류할 수 있으며, 외부 제공자 호출에는 비용과 데이터 처리 정책이 적용됩니다.
## 5. 검증과 증거 보관

[CI 실행](https://github.com/taehyeon-git/SecRAGraph/actions/runs/37821416468)은 `v0.1.0` 태그 대상 커밋에서 테스트·품질·의존성 감사·컨테이너 빌드가 모두 통과했습니다. 같은 커밋의 [보안 셀프 스캔](https://github.com/taehyeon-git/SecRAGraph/actions/runs/37821416381)은 SARIF 생성·검증·업로드에 성공했고, [Code Scanning](https://github.com/taehyeon-git/SecRAGraph/security/code-scanning)에 결과가 반영되었습니다. 2026-10-09 확인 당시 열린 경고는 0건이지만, 이는 취약점이 없다는 보증이 아닙니다. [v0.1.0 릴리스](https://github.com/taehyeon-git/SecRAGraph/releases/tag/v0.1.0)도 공개했습니다.

위 링크는 **과거 v0.1.0 커밋**의 증거입니다. 현재 `main`에 추가한 토큰·코퍼스 동기화·선택 평가·Compose 스모크는 [최신 CI 실행](https://github.com/taehyeon-git/SecRAGraph/actions/workflows/ci.yml)에서 별도로 확인해야 합니다. `quality` 작업의 `rag`/`scanner` JSON·Markdown 아티팩트는 신뢰된 `main` push에서만 보관하고 PR에서는 실행·검증만 합니다. 이 아티팩트는 합성/결정적 평가 결과이지 실제 LLM 성능이나 외부 벤치마크 점수가 아닙니다.

2026-10-09 로컬 검증에서는 기존 볼륨을 건드리지 않고 별도 Compose 프로젝트와 포트로 PostgreSQL/Qdrant 통합 테스트 스택 및 API/웹 데모 스택을 실행했습니다. API `/health/ready`는 PostgreSQL과 Qdrant가 모두 준비됐다고 응답했고, Streamlit 헬스 엔드포인트도 HTTP 200을 반환했습니다. 합성 예제를 다시 스캔한 결과는 `PY001`, `PY002`, `SEC001` 세 건이었으며 `SEC001` 증거는 가려져 있었습니다. 전체 pytest는 602건 통과, Windows에서 심볼릭 링크 생성이 불가능해 4건 건너뜀, `security_review` 커버리지 90%였고, 통합·E2E만 별도로 실행한 47건도 통과했습니다. CI용 API 시작·준비 확인·종료 코드를 별도 로컬 포트에서 실행했을 때 실제 API 통합 테스트 2건이 통과했고 종료 뒤 포트가 해제됐습니다. `src` 셀프 스캔 SARIF는 `scripts/validate_sarif.py` 검증을 통과했습니다. 이 결과는 로컬 실행에만 해당합니다.

2026-10-10 커밋 `c3aaa17`에서 수행한 통합 로컬 검증에서는 전체 pytest 818건 통과·8건 건너뜀, `security_review` 커버리지 89%였습니다. 키 없는 RAG 근거 사례는 4/4, 합성 스캐너 사례는 39/39였고 스캐너 집계는 TP 18건·FP 0건·FN 0건이며 생성된 증거 파일은 바이트 단위로 재현됐습니다. Ruff·mypy·Bandit 검사, SARIF 생성·검증, 의존성 감사(`audit_clean`), 로컬 런타임 이미지 빌드도 통과했습니다. 이 수치는 해당 커밋의 로컬 결과이며, 합성 사례 집계는 임의 저장소의 정확도나 실제 취약점 존재를 보증하지 않습니다.
