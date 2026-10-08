# Text2SQL 보안 경계

이 기능은 스캔 결과 수정 권고를 생성하지 않습니다. `POST /v1/knowledge/query`의 LangGraph가 구조화된 CVE/CWE 질문을 `text2sql`로 분기할 때만 사용됩니다. 검증 대상은 [text2sql.py](../src/security_review/intelligence/text2sql.py), [sql_guard.py](../src/security_review/intelligence/sql_guard.py), [storage/intelligence.py](../src/security_review/storage/intelligence.py)에 구현되어 있습니다.

## 실행 순서

1. ChatModel은 `intel.cwe`와 `intel.cve`의 열 정의 및 행 제한을 받은 뒤 SQL 후보 하나를 생성합니다. 질문은 신뢰하지 않는 데이터입니다.
2. SQLGlot으로 PostgreSQL 구문을 파싱해 정확히 하나의 `SELECT`인지 확인합니다. 원본 모델 출력은 실행하지 않습니다.
3. AST는 스키마가 명시된 `intel.cwe`/`intel.cve`만 허용합니다. 데이터 변경·DDL·잠금·주석·와일드카드·허용되지 않은 함수·매개변수 및 복수 문장을 거절합니다. `LIMIT`은 숫자 리터럴이어야 하며 설정된 행 상한 이하로 낮춥니다.
4. 검증해 다시 렌더링한 SQL을 전용 `secragraph_text2sql` 로그인으로 실행합니다. [역할 부트스트랩](../infra/postgres/init/002_reader_login.sh)은 비관리자 역할과 기본 읽기 전용 트랜잭션·시간 제한을 설정합니다. [마이그레이션](../migrations/versions/20260920_0002_security_intelligence.py)은 `intel` 스키마 사용 및 두 테이블의 `SELECT`만 reader에 부여하고 `app` 스키마 접근을 제거합니다.
5. 저장소 어댑터가 `SET TRANSACTION READ ONLY`와 로컬 `statement_timeout`을 설정한 뒤 결과를 지정된 최대 행 수만큼 가져옵니다. 제한된 행과 검증 SQL은 별도의 답변 모델에 데이터로 전달됩니다. 답변 모델에는 DB 도구 접근이 없습니다.

기본 설정은 SQL 생성 최대 2회, `sql_row_limit=100`, `sql_statement_timeout_ms=2000`입니다([config.py](../src/security_review/config.py)). 설정 자체도 상한을 검증합니다. 안전하지 않은 SQL 후보는 이유 코드만 사용해 재시도합니다. 유효한 SQL을 실행한 뒤에는 실행 실패나 답변 모델 실패를 이유로 쿼리를 무한 재시도하지 않습니다. 모든 후보가 거절되면 조회 없이 안전한 실패 답변과 경고를 반환합니다. DB/제공자 장애는 지식 API에서 안전한 오류로 표시합니다.

## 통제의 이유와 남은 위험

프롬프트 지시만으로 SQL 안전을 보장하지 않습니다. SQLGlot AST, 명시적 테이블/함수 허용 목록, 제한된 `LIMIT`, DB의 실제 `SELECT` 권한, 읽기 전용 트랜잭션, `statement_timeout`을 겹쳐 적용합니다. 검증을 통과한 SQL도 집계·조인 비용이나 잘못된 질문 때문에 느리거나 오해를 부를 수 있습니다. 시간·행 한도와 수동 검토가 필요합니다.

데모 [CSV](../data/samples/README.md)는 합성 데이터입니다. 실제 CVE/CWE 최신성, 완전성, 라이선스는 운영자가 가져오는 소스에 달려 있습니다. 수집된 데이터의 행은 답변 모델에게도 신뢰하지 않는 입력이므로, 내용 속 지시문은 실행 명령으로 취급하지 않습니다. SQL 문장과 표 데이터는 제한된 provenance로 반환될 수 있어 질문과 저장 데이터에 기밀 정보를 넣지 않아야 합니다. 더 넓은 자산·공격면은 [위협 모델](threat-model.md)을 보세요.
