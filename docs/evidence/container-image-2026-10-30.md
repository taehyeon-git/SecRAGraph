# 런타임 이미지 검사와 SBOM: 2026-10-30

## 대상과 재현 입력

이 기록은 `main`의 `c8f7800ebd740298478a6c705e51f0c0e04b51f3`에서
시작한 SecRAGraph 런타임 Dockerfile을 로컬 Docker Desktop Linux 엔진
29.9.2로 `--provenance=false --platform linux/amd64 --target runtime` 빌드한
**수정 전 한 이미지**의 결과입니다. CI는 PR과 `main`에서도 동일한 검사
절차를 실행하도록 구성했습니다. 회원 업로드 이미지나 다른 아키텍처의
결과가 아닙니다. 아래 수치는 현재 Dockerfile에 Debian 보안 업데이트를
적용하기 전의 로컬 기준선 스냅샷입니다.

| 항목 | 검증값 |
| --- | --- |
| Trivy | `0.76.1` |
| 공식 Linux 자산 SHA-256 | `c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0` |
| 로컬 검증 Windows 자산 SHA-256 | `1051f49cb22d5284f43425f72aad9cda63ca12ceb92e7caa06903490c82dc9bf` |
| Trivy DB `UpdatedAt` (UTC) | `2026-10-29T13:09:46.269823Z` |
| Docker 로컬 ID (OCI manifest) | `sha256:e70f14dbf89234969281db710e8e690c839f70c4355976300c08c1dcba50bc09` |
| 이미지 config digest | `sha256:6319980c53f0801c356b9b899e8d3b62f39bc1bb206a22dfa70c5a2a226f67b3` |
| `docker save` tar SHA-256 | `563577a7272c04a25b58853278e26cdb52bbb9725ddd614412d5a42d2f4908e2` |
| CycloneDX JSON SHA-256 (최종 로컬 실행) | `96e5fa623cd4220c8f5e036b45ad21112d2633f35099e04c6a35a9df2712f251` |

Docker 로컬 ID, 이미지 config digest와 tar 해시는 서로 다른 대상의
식별자입니다. OCI index·manifest·config·layer를 확인하고 Trivy JSON과
SBOM의 이미지 ID가 config digest와 같은지 검증했습니다. 태그나
레지스트리 digest로 바꿔 부르지 않습니다. CycloneDX의 `serialNumber`는
실행마다 새 UUID가 될 수 있어 SBOM 파일 해시는 **해당 실행의 바이트**를
묶는 값이지 재실행 때 같은 해시가 나온다는 뜻은 아닙니다.

## 수정 전 로컬 실측 결과

Trivy JSON의 `Vulnerabilities` 기록 **384건**, 이미지 설정
`Misconfigurations` **0건**을 정규화했습니다. `Results`에는 Debian
`os-pkgs`, Python 및 Go 바이너리 `lang-pkgs`, 이미지 `config` 검사가
포함되었습니다. 출력은 `Finding` 384건과 완료된 이미지
`ScanExecution` 한 건으로 재구성됐습니다.

| 원본 심각도 | 기록 수 |
| --- | ---: |
| CRITICAL | 6 |
| HIGH | 107 |
| MEDIUM | 155 |
| LOW | 111 |
| UNKNOWN | 5 |

CycloneDX 1.7 SBOM에는 **구성요소 386개**, dependency 387개와
vulnerability entry 225개가 있습니다. SBOM의 취약점 표현·중복 단위는
Trivy JSON 기록과 달라 225와 384를 동일 분모로 비교하지 않습니다.
원본 `UNKNOWN` 5건은 보고서에 원래 심각도를 표시하면서 플랫폼 위험도
계산에는 보수적으로 `MEDIUM`을 적용합니다.

현재 [기준선](../../data/security/container-image-baseline.json)은 HIGH
107건, CRITICAL 6건, UNKNOWN 5건의 안정된 권고/패키지/설치 버전/검사 유형
식별자 **118개**를 담습니다. 파일 SHA-256은
`56b9c4dd81da21186fdc64351729558e59117a175c6563300cb4c9529cd3a6f6`입니다.
같은 실측 결과로 초기 기준선을 만들었으므로 기준선 대비 신규 건은
0건입니다. 별도 합성 신규 HIGH 사례를 추가했을 때 게이트가 실패하는
테스트를 확인했습니다. 이후 CI는 기준선 파일의 PR 변경을 실제 base
커밋과 비교해 막고, 새로운 HIGH·CRITICAL·UNKNOWN 식별자 또는 위험한
이미지 설정을 차단합니다. 기준선 파일에는 118개 식별자가 남지만 수정된
취약점은 새 이미지의 보고서에 나타나지 않습니다.

## 새 권고와 수정

새 Trivy DB (`UpdatedAt` `2026-10-29T19:18:50.96912695Z`)로 같은
수정 전 이미지를 다시 검사했을 때 `tzdata 2026c-0+deb12u1`에 대한
`DLA-4867-1`이 1건 추가됐습니다. 원본 심각도는 `UNKNOWN`이고
Trivy가 기록한 수정 버전은 `2026f-0+deb12u1`입니다. 기존
`DLA-4854-1`의 수정 버전은 `2026e-0+deb12u1`입니다. 새 권고는
게이트가 의도대로 차단했습니다.

[Debian 보안 저장소의 bookworm-security Packages.xz](https://deb.debian.org/debian-security/dists/bookworm-security/main/binary-amd64/Packages.xz)에
`tzdata 2026f-0+deb12u1`과 패키지 SHA-256
`3254eb870c8a949518214805aee5e4276af7699988ea8b9a3a583cd0f1eab31c`가
기재돼 있고, [Debian 패키지 뉴스](https://tracker.debian.org/pkg/tzdata/news/)는
2026-10-29 oldstable-security 반입을 기록합니다. 그래서 Dockerfile의
runtime 단계에서 동일 배포판의 해당 버전을 정확히 설치하도록 수정했습니다.
설치가 실패하면 빌드도 실패합니다. 아래 CI 결과로 새 이미지의 실제
검사 수치와 게이트 결과를 별도로 확인합니다.

심각도는 Trivy가 선택한 데이터 원천의 권고 수준이며 실제 서비스에서
악용 가능한 113개 취약점이 확인됐다는 뜻은 아닙니다. 6개 CRITICAL
기록 중 4개는 Trivy에 수정 버전이 있고, 2개는 기록된 수정 버전이
없습니다. 우선 수정 버전이 있는 Debian `perl-base`와 도구에 포함된
Go 표준 라이브러리를 갱신하고 재스캔해야 합니다. `libsqlite3-0`와
`zlib1g`의 NVD CRITICAL 기록은 배포판 권고·실제 영향 범위를 사람
검토로 확인해야 합니다. 기준선은 이러한 검토를 대신하지 않습니다.

## 실행·공개 경계

CI는 검증한 Trivy 바이너리와 DB를 준비한 뒤 같은 tar에서 JSON 검사와
CycloneDX 생성을 별도로 실행합니다. 분석 단계에는 `--input`,
`--skip-db-update`, `--skip-java-db-update`, `--skip-check-update`,
`--offline-scan`, `--disable-telemetry`, `--skip-version-check`를 사용합니다.
원본 Trivy JSON의 `Metadata.ImageConfig`에는 이미지 환경변수가 있을 수
있어 공개 아티팩트에는 넣지 않습니다. `main` 아티팩트는 검증·정규화한
JSON·Markdown·SARIF, CycloneDX SBOM과 해시/DB/기준선 비교 manifest로
제한합니다. SARIF는 패키지의 논리적 위치를 기록하며 현재 소스 줄의
GitHub Code Scanning 주석으로 업로드하지 않습니다.

로컬 재현 명령은 [운영 문서](../operations.md#runtime-image-evidence)에
있습니다. 시간이 지나 DB가 갱신되면 권고 수가 달라지는 것이 정상이며,
새 권고가 기준선 밖으로 나타나면 CI가 검토를 요구합니다.
