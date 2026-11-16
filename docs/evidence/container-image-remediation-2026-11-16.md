# 런타임 이미지 보안 권고 재검사: 2026-11-16

## 비교 조건과 결과

기존 이미지와 수정 이미지를 모두 `linux/amd64`에서 `docker save`한 뒤, **같은 Trivy 0.76.1 DB** (`UpdatedAt=2026-11-16T01:11:02.624123Z`)로 검사했다. 두 실행 모두 이미지 취약점·설정 검사와 CycloneDX SBOM 생성을 완료했다. 이 기록은 로컬 사전 검증이며 PR·`main` CI 결과와 구분한다. 이전 [이미지 기록](container-image-2026-11-16.md)은 날짜와 DB가 달라 직접적인 개선율 비교에 사용하지 않았다.

| 항목 | 기존 이미지 | 수정 이미지 |
| --- | ---: | ---: |
| Trivy 취약점 기록 | 286 | 206 |
| HIGH · CRITICAL · UNKNOWN | 95 | 49 |
| 그중 Gitleaks Go 바이너리 | 42 | 0 |
| 그중 Debian 패키지 | 52 | 48 |
| 그중 Checkov `ecdsa` | 1 | 1 |
| 이미지 설정 차단 항목 | 0 | 0 |
| CycloneDX 구성요소 | 348 | 347 |

수정 이미지의 심각도는 HIGH 44건, CRITICAL 0건, UNKNOWN 5건이다. 기존 이미지의 심각도는 HIGH 86건, CRITICAL 1건, UNKNOWN 8건이었다. 전체 기록 80건 감소 중 74건은 Gitleaks 바이너리의 Go 권고, 6건은 제거한 Debian `mount` 패키지의 권고다. 이 수치는 **패키지·권고 기록 수**이며 실제 악용 가능성이나 일반적인 스캐너 탐지율이 아니다. 기존 95개 식별자를 담은 CI 기준선은 수정하지 않았고, 수정 이미지에 새 고위험 식별자 0건·차단 대상 설정 0건으로 게이트를 통과했다.

| 재현 식별자 | 값 |
| --- | --- |
| 기존 로컬 이미지 ID | `sha256:91175ef606b45c0f623b592e6cf7f6aa536cccf0e1320d6c67e4b7bff682a13f` |
| 수정 로컬 이미지 ID | `sha256:e563df282e1e74eea42c1b64fd07ede583ec6288a04c767ced8c91b8e025e875` |
| 기존 이미지 tar SHA-256 | `0b978d1942436f661f1b490bebd29eaaa890897eeda8fe3b1bcfa8da1249bafa` |
| 수정 이미지 tar SHA-256 | `28d5d4949e7d25bf01a2104d319fb68504a05e815c72d19fd9a64666e126aebd` |
| 수정 이미지 config digest | `sha256:b91ef19ba1076810e1e2d497411dd8ca3b5c6ced435fa7d1234f29d33020e7d9` |
| 수정 이미지 SBOM SHA-256 | `488251a2901b2180cb98850bf5c16dc20a9cad966975789a3c0ee8fcf0f9179b` |

## Gitleaks: 재빌드와 탐지 결과 비교

[공식 v8.30.1 릴리스](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1)의 소스 커밋 `83d9cd684c87d95d656c1458ef04895a7f1cbd8e`을 정확히 확인하고, `Dockerfile`의 빌더에서 고정된 Go 1.27.4 이미지와 체크섬을 확인한 `go.mod`·`go.sum`으로 재빌드한다. 이 바이너리는 **SecRAGraph에서 재빌드한 파생물**이며 공식 배포 바이너리라고 표시하지 않는다. 최종 이미지에 들어간 바이너리의 SHA-256은 `696f76e95d79dd27ded16fef4f3dc98ee03251f06fa73cfc45c6e40fdcc76791`이다.

이미지에서 꺼낸 바이너리의 `go version -m`에는 Go 1.27.4, `golang.org/x/crypto` 0.59.0, `x/text` 0.44.0, `x/sys` 0.50.0, `github.com/klauspost/compress` 1.20.2, `github.com/ulikunitz/xz` 0.5.15, `github.com/nwaples/rardecode/v2` 2.2.2가 기록됐다. Linux 네이티브 소스 체크아웃에서 `go test ./...`와 실제 빌드에 쓰는 `gore2regex` 태그의 핵심 패키지 테스트를 통과했다.

공식 바이너리와 최종 이미지 바이너리를 [작성자 스캐너 사례](../../data/evaluation/multiengine_cases.json) 29건에 각각 적용한 결과, 모두 완료됐고 규칙 ID·경로·줄 위치가 같았다. 각 바이너리는 동일한 양성 비밀 사례 1건을 찾았으며 음성 대조군을 추가 탐지하지 않았다. Git 이력의 삭제 파일·병합 커밋이 있는 **같은 임시 저장소**를 두 바이너리로 검사해 각각 선택 커밋 7개, 탐지 3건으로 통과했다. CI는 커밋·규칙 ID·경로·줄 위치까지 직접 비교한다. 로컬 음성 대조로 한 보고서의 줄 위치를 일부러 바꿨을 때 이 동등성 검사가 실패함도 확인했다. 비교 파일은 비밀 원문 없이 건수·SHA-256만 저장한다. 이 동등성 검사는 해당 사례에 한정된다.

## Debian: 제거 가능한 패키지만 제거

`apt-get -s purge mount`가 `mount`만 제거하고 필수 패키지를 지우지 않음을 확인한 뒤 런타임 이미지에서 제거했다. 수정 이미지의 `dpkg-query`에는 `mount`가 없고 `login`, `util-linux`, `libmount1`은 남아 있다. `login` 제거는 보호 패키지 경고가 발생한다. 추가로 `ncurses-bin`·`ncurses-base` 제거는 필수 패키지 경고가, `libudev1`·`libacl1`·`libsqlite3-0`·`libsystemd0` 제거는 의존성 해결 실패가 발생해 적용하지 않았다. 다른 배포판의 패키지를 섞지 않았다.

Debian 고위험·미상 기록은 52건에서 48건으로 줄었지만 **서로 다른 권고 14개는 그대로**다. 특히 `util-linux` 계열의 CVE-2026-76642·78408·78409·78410은 각각 9개 패키지에서 8개 패키지로 줄었을 뿐이다. [Debian 보안 추적기](https://security-tracker.debian.org/tracker/CVE-2026-76642)의 Trixie 수정 상태를 계속 확인해야 한다. 나머지 권고는 glibc, ncurses, SQLite, systemd, ACL, dpkg, Perl 패키지에 있다. 패치가 없거나 필요한 패키지를 억지로 삭제하지 않는다.

## Checkov: 남은 `ecdsa` 권고

Checkov 3.3.30의 별도 가상환경에는 `ecdsa` 0.19.2가 설치돼 있고 CVE-2024-23342 HIGH 1건이 남는다. 설치된 Checkov 코드에서 `ecdsa` import는 `common/external_checks/verification/keys.py`와 `verifier.py`에 있으며, 공개키 서명 **검증** 경로에 사용된다. [권고](https://github.com/advisories/GHSA-wj6h-64fc-37mp)는 서명·키 생성·ECDH의 타이밍 문제를 설명한다. SecRAGraph의 Checkov 어댑터는 제출된 `.checkov.yaml`을 제외하고 기본 제공 검사만 임시 디렉터리에서 실행하며, 외부 검사 관련 환경변수를 제거한다. 이 경계를 회귀 테스트로 확인했다. 따라서 현재 호출 경로에서 권고의 영향을 낮게 보지만, 취약 패키지가 설치돼 있다는 사실과 Trivy finding은 그대로 공개한다. [상위 프로젝트의 수정 요청](https://github.com/tlsfuzzer/python-ecdsa/issues/381)이 해결되거나 Checkov가 해당 의존성을 안전하게 교체할 때 재평가한다.

## 재현

[운영 문서](../operations.md)의 이미지 검사 절차로 두 이미지를 같은 DB에서 검사한 뒤 다음 게이트를 실행했다.

```text
python -m scripts.ci_container_image --manifest build/evidence/new-scan/container.manifest.json --baseline data/security/container-image-baseline.json --base-sha 68bd81e3d49a67c9c38040799db33a4e20c9717b --repo-root .
container_gate: severe_total=49 baseline_records=95 new_severe=0 blocking_config=0
```

수정 이미지로 격리된 Compose 스택을 구동해 API·웹 준비, 회원 로그인, ZIP 업로드 검사와 보고서 저장·조회를 통과했다. 정규화된 JSON·Markdown·SARIF·SBOM과 manifest는 로컬 `build/evidence/` 아래에 두었으며 원시 Trivy 출력은 공개하지 않았다. CI는 PR과 `main`에서 새 이미지를 다시 빌드·검사하므로 해당 실행의 DB와 권고 수는 달라질 수 있다.
