# 출처와 기여

SecRAGraph는 보안 문서 RAG/질의와 소스 검사 아이디어를 하나의 새 백엔드·DevSecOps 구현으로 정리한 포트폴리오입니다. 이 문서는 선행 작업의 저작 주체, 확인 가능한 개인 기여, 새 구현, 자료 권리를 구분합니다.

## 선행 프로젝트

| 프로젝트 | 관계와 확인 가능한 기여 |
| --- | --- |
| [`ye11an9/rag-documents`](https://github.com/ye11an9/rag-documents) | 여러 사람이 함께 만든 교육용 팀 프로젝트입니다. [팀 기여자 기록](https://github.com/ye11an9/rag-documents/graphs/contributors)을 함께 보세요. `taehyeon-git` 이름으로 작성된 대표 커밋에는 [Streamlit 테마 변경](https://github.com/ye11an9/rag-documents/commit/05e1e98)과 [LangGraph CVE/CWE 정렬](https://github.com/ye11an9/rag-documents/commit/6ae53f1)이 있습니다. 해당 Git 기록의 저자 이메일은 `t.j9431@gamil.com`으로 잘못 입력되어 GitHub 계정의 연결 기여자 목록에 표시되지 않을 수 있습니다. 이 사실은 팀 전체 결과의 단독 저작을 뜻하지 않습니다. |
| [`taehyeon-git/security-agent-langgraph`](https://github.com/taehyeon-git/security-agent-langgraph) | 개인 보안 에이전트 실습 저장소입니다. 강의 노트북 템플릿을 포함하므로, 그 토대나 모든 기초 아이디어를 개인이 처음부터 독자적으로 만든 것으로 주장하지 않습니다. |

두 선행 저장소는 각각 별도의 권리와 기여자를 가집니다. 공개 GitHub 저장소의 라이선스 정보만으로 코드·데이터 재배포 권한을 확인할 수 없으므로, 선행 저장소의 코드, PDF, 스크린샷, 이미지, 문서 자산을 이 저장소로 복사하거나 SecRAGraph의 MIT 범위에 포함하지 않았습니다. 이 저장소의 구현과 데모 지침은 새로 작성했습니다.

## SecRAGraph에서 새로 작성한 범위

공유 도메인 모델과 위험 점수 계약, 텍스트 정적 스캐너와 증거 마스킹, 안전한 파일/ZIP 업로드, FastAPI·Typer CLI·Streamlit 연결, PostgreSQL 보고서·감사 저장, 별도 권한의 guarded Text2SQL, Qdrant/모델 어댑터 경계, 두 개의 LangGraph 워크플로, JSON·Markdown·SARIF 보고서, 테스트, 비루트 컨테이너·Compose, CI 및 보안 셀프 스캔 정의를 이 저장소에서 구현했습니다. 스캔 그래프의 Qdrant 검색은 문서 출처를 추가하며, Text2SQL은 별도 지식 질의 경로입니다. 두 경로를 하나의 LLM 수정 권고 생성 기능처럼 소개하지 않습니다.

`data/samples`의 CVE/CWE CSV는 실제 취약점 레코드가 아닌 합성 예시입니다. `data/knowledge`의 Markdown은 이 데모를 위해 새로 쓴 문서입니다. 제3자의 보안 문서나 실제 데이터는 재배포하지 않습니다. 문서 수집은 사용자가 적법한 원본을 확보해 직접 실행하며, 현재 UTF-8 Markdown 형식만 지원합니다.

## 라이선스와 인용

[MIT 라이선스](../LICENSE)는 **새로 작성한 SecRAGraph 코드**에만 적용됩니다. 선행 프로젝트의 소스·데이터 및 제3자 자료의 이용·수정·재배포는 각 원저작자의 허락과 해당 자료의 조건을 따릅니다. README와 이 문서의 링크는 출처 표시이며 권리 이전이나 재라이선스를 의미하지 않습니다. 실무나 연구에 외부 CVE/CWE 데이터를 사용한다면 게시자의 최신 이용 조건과 `source_url`을 확인하세요.
