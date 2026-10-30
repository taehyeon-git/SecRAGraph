# Docker Compose 선언 정책 검사 증거

## 범위

`compose-policy` 버전 `2026.10.30.1`은 이름이 확인된 Compose YAML 파일의 **명시적 서비스 설정** 10종을 검사합니다. 대상 코드를 실행하거나 `docker compose config`를 호출하지 않습니다. `include`, `extends`, 환경 변수 치환, 파일 병합과 실제 배포 상태는 해석하지 않습니다. 확인하지 못한 부분은 `partial`과 고정 이유 코드로 기록합니다. [설계와 규칙 목록](../design/compose-iac.md)에 입력 한도와 판단 경계가 있습니다.

기존 Checkov는 Compose 전용 프레임워크가 없으므로, Compose 파일을 Checkov의 적격 파일에서 제외했습니다. Checkov에는 검증된 나머지 설정 파일만 별도 작업 디렉터리로 복사해 전달합니다. 두 엔진의 대상·확인 파일·실행 상태는 같은 `ScanExecution` 형식으로 JSON·Markdown·SARIF 보고서에 남습니다.

## 작성자 사례의 직접 대조

[다중 엔진 사례 manifest](../../data/evaluation/multiengine_cases.json)에 한 파일씩 담은 Compose 사례 11개가 있습니다. 위험 설정 10개 사례와 정상 대조 1개에서 규칙 10개를 모두 평가하므로 **110개 규칙·파일 평가, 양성 평가 10개(예상 줄 11개), 음성 평가 100개**입니다. 실제 `ComposePolicyAdapter.scan_snapshot`을 각 사례의 파일에 호출해 11개 실행이 모두 `completed`이고 110개 평가의 규칙 ID·파일·시작 줄이 예상과 일치함을 확인했습니다. 이 대조는 작성자가 만든 회귀 사례의 직접 실행 결과이며 실제 저장소 탐지율이 아닙니다.

CI의 전체 `scan_path` 평가와 Compose 전용 증거 게이트는 [워크플로](../../.github/workflows/ci.yml)에서 같은 manifest를 사용합니다. 전체 평가에는 Opengrep·Gitleaks·Checkov의 기존 사례도 포함되며, 해당 엔진의 알려진 오경보·누락을 Compose 점수에 합치지 않습니다.

[PR CI 품질 작업](https://github.com/taehyeon-git/SecRAGraph/actions/runs/41018714959/job/123940852364)의 고정 스캐너 이미지에서 25/25 사례와 152/152 라벨이 채점됐고, manifest SHA-256은 `9fd021037109a5d1703f4d02b5372157befb99dc80af5962583d29b94244dbc2`였습니다. Compose 엔진은 25회 실행 중 11개 파일을 적격·확인했고 11회 `completed`였습니다. **Compose 라벨 110개에서 TP=11, FP=0, FN=0**, 누적 실행 시간 11ms였으며 새 미평가 finding은 전체 사례에서 0개였습니다. 이 수치는 작은 작성자 회귀 세트에만 적용됩니다.

| Compose 규칙 | TP | FP | FN | 채점 평가 |
| --- | ---: | ---: | ---: | ---: |
| `CAP_ADD_DANGEROUS` | 1 | 0 | 0 | 11 |
| `DOCKER_SOCKET` | 1 | 0 | 0 | 11 |
| `EXPLICIT_ROOT_USER` | 2 | 0 | 0 | 11 |
| `HOST_IPC` | 1 | 0 | 0 | 11 |
| `HOST_NETWORK` | 1 | 0 | 0 | 11 |
| `HOST_PID` | 1 | 0 | 0 | 11 |
| `HOST_ROOT_MOUNT` | 1 | 0 | 0 | 11 |
| `PRIVILEGED` | 1 | 0 | 0 | 11 |
| `PROVIDER` | 1 | 0 | 0 | 11 |
| `UNCONFINED_PROFILE` | 1 | 0 | 0 | 11 |

## 라벨 없는 저장소 관찰

이 저장소의 추적 중인 Compose 파일 `compose.yaml`, `infra/dast/compose.yaml`, `tests/compose.integration.yaml`을 원래 상대 경로 그대로 임시 스냅샷에 복사해 어댑터를 한 번 실행했습니다. 검사 파일은 작업 브랜치 커밋 `74dd932208ae6e7d9d0dc8cdd081fd52cc7cc8e5`의 내용과 같았습니다. 결과는 적격 3개, 확인 2개, finding 0개, `partial`, 110ms였습니다. 메인 `compose.yaml`은 YAML 별칭을 사용해 `alias_unresolved`로 건너뛰었고, 나머지 두 파일의 명시적 설정만 확인했습니다. finding 0개는 안전 판정이 아니며 이 저장소에 독립적인 정답 라벨이 없어 TP·FP·FN은 계산하지 않습니다.

## 해석 한계

- 보고된 finding은 **선언된 설정**을 뜻합니다. 다른 파일의 override로 바뀌거나 실제 실행에서 적용되지 않을 수 있습니다.
- 같은 디렉터리에 Compose 파일이 여러 개 있거나 별칭·동적 값·외부 참조가 있으면 완전한 설정을 확인하지 못했다고 표시합니다. 다른 디렉터리의 파일은 별도 후보로 다루지만, 호출자가 `-f`로 조합했는지는 알 수 없습니다.
- 규칙 10개에 없는 위험 설정은 이 엔진의 검사 대상이 아닙니다. 설정 파일 검사, 이미지 패키지 검사, 실행 중 API 검사는 각각 다른 입력과 근거를 사용합니다.

Docker의 [Compose 서비스 참조](https://docs.docker.com/reference/compose-file/services/)와 [Compose 신뢰 모델](https://docs.docker.com/compose/trust-model/)을 규칙 경계의 1차 자료로 사용했습니다.
