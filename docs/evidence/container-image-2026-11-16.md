# 런타임 이미지 재검사: 2026-11-16

## 범위와 재현성

`main`의 `8cab336dedbd7b9a2d777cddbe2fd7bdc8d48e97`에서 만든 수정 브랜치를
Linux/amd64 Docker 이미지로 빌드하고, Trivy 0.76.1과
`UpdatedAt=2026-11-15T12:50:30.599818+00:00` DB로 검사했다. 이 기록은
로컬 사전 검증이며 PR·병합 후 CI 실행 결과와 구분한다.

| 항목 | 값 |
| --- | --- |
| 공식 Python 기반 이미지 | `python:3.11-slim-trixie@sha256:07d4824036af339fa1b6ef769cc99d9c10a141769538b52b3b597c84f7a7b535` |
| Docker 로컬 이미지 ID | `sha256:91175ef606b45c0f623b592e6cf7f6aa536cccf0e1320d6c67e4b7bff682a13f` |
| 이미지 config digest | `sha256:1109c2e3db09045c65db9f16dfb81595830d70a3f240fe9365917c5bc2bbab87` |
| `docker save` tar SHA-256 | `c7b6239488ba596733ab70a98ceac86302e583b0fe2debd5791b9123515c422d` |
| CycloneDX SBOM 구성요소 | 348개 |
| 이미지 설정 검사 결과 | 차단 대상 0건 |

이미지와 Trivy DB를 고정한 해당 실행의 취약점 기록은 **283건**이었다:
LOW 67, MEDIUM 121, HIGH 86, CRITICAL 1, UNKNOWN 8.
게이트가 추적하는 HIGH·CRITICAL·UNKNOWN은 **95건**이며 Debian OS 패키지
52건, 동봉 Gitleaks Go 바이너리 42건, Checkov의 `ecdsa` 1건이다.
이전 2026-11-15 예약 CI에서는 오래된 Bookworm 기반 이미지에 173건의
게이트 대상 기록과 기준선 밖 81건이 나타나 실패했다. 이 수치는 DB·이미지
조건이 달라 직접적인 취약성 개선율로 해석하면 안 된다.

## 수정과 남은 위험

- 취약점 8건이 보고된 잠금 의존성 `pypdf 6.21.2`, `opentelemetry-api
  1.45.1`을 각각 `6.21.4`, `1.45.2`로 갱신했다. 변경된 잠금 파일로
  `scripts/ci_dependency_audit.py`의 OSV 검사를 통과했다.
- 지원되는 공식 Python 3.11 Trixie 이미지를 고정하고, Debian 보안 패치
  `zlib1g=1:1.3.dfsg+really1.3.1-1+deb13u1`을 설치했다. 사용하지 않는
  전역 Python 패키징 도구는 런타임에서 제거했다.
- Checkov 별도 가상환경의 `soupsieve`를 Python 3.11에서 4.1.1로 올렸다.
  이미지 속 Opengrep·Gitleaks·Checkov와 앱 의존성의 실행을 확인했다.
- 현재 공식 Gitleaks 8.30.1 바이너리에는 Go 관련 42건이 남는다.
  Trivy에 수정 버전이 기록되어도 현재 배포된 공식 바이너리에 적용된 것은
  아니다. Debian 52건과 Checkov `ecdsa` 1건에도 이 검사 시점의
  수정 버전이 기록되지 않았다. 이들은 해결 완료로 취급하지 않는다.

새 기준선은 이 실행의 95개 정확한 식별자만 담고 SHA-256이
`0da9f8d9c2897b52a9f1de3dda9ba67dac7e9e69289a4eee56a67ef16b9d6a71`이다.
이전 기준선 SHA-256
`9a2f7f1e90f7f6a82cdad299cb2df029a92595a99aa9bebb6449c0a35e013283`에서
이번 기준선으로의 변경은 앞의 `main` 커밋을 기반으로 한 PR과 첫 push에서만
정확한 두 파일 해시로 허용한다. 이후 새 HIGH·CRITICAL·UNKNOWN 식별자는
다시 게이트를 실패시킨다. 기준선은 스캔 결과를 지우거나 위험이 없다고
판정하지 않는다. 권고 수는 DB에 따라 변하며 실제 악용 가능성 평가는 별도다.
