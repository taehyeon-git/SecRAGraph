# 기여 안내

SecRAGraph는 교육 및 포트폴리오 목적의 방어적 보안 검토 도구입니다. 작은 변경과 재현 가능한 테스트를 환영합니다.

1. Python 3.11 이상과 `uv`를 준비하고 저장소 루트에서 `uv sync --frozen --dev`를 실행합니다.
2. 새 규칙·API·저장소 경계의 동작을 바꿀 때는 실패하는 테스트를 먼저 추가합니다. 제출 전 `uv run ruff format --check .`, `uv run ruff check .`, `uv run mypy src apps`, `uv run pytest`를 실행합니다.
3. 변경 설명에는 입력, 예상 출력, 보안 경계, 실패 시 동작을 적습니다. SARIF나 API 형식을 바꾸면 동일한 canonical report의 다른 표현도 확인합니다.
4. 실제 자격 증명, 개인 데이터, 제3자 문서·PDF·스크린샷, 재배포 권리가 확인되지 않은 코드를 커밋하지 마세요. 데모에는 합성 데이터와 가짜 값만 사용합니다.

보안 취약점은 공개 PR이나 이슈에 상세히 게시하기 전에 [보안 정책](SECURITY.md)의 비공개 제보 절차를 따르세요. 기존 팀 프로젝트와 개인 실습의 권리는 [출처와 크레딧](docs/origins-and-credits.md)을 참고하세요.
