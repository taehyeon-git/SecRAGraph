# Docker Compose IaC policy adapter

## Why this phase exists

The current snapshot pipeline passes YAML to Checkov as Kubernetes and
CloudFormation candidates. Checkov has no Docker Compose framework in its
[supported framework list](https://www.checkov.io/2.Basics/CLI%20Command%20Reference.html),
so a Compose file can appear eligible without a Compose policy being evaluated.
This phase adds a small, explicit `compose-policy` configuration engine to the
shared API/CLI/LangGraph scan path. It does not claim to validate a fully
resolved deployment or a running container. The existing Trivy image scan
remains a separate check of the built runtime image.

## Scope and trust boundary

Recognize case-insensitive basenames `compose.yml`, `compose.yaml`,
`docker-compose.yml`, `docker-compose.yaml`, and
`compose.*.yml`/`.yaml` or `docker-compose.*.yml`/`.yaml` where `*` is one or
more ASCII letters, digits, hyphens, underscores or periods. This includes
`compose.override.yaml` and `docker-compose.test.yml`; it does not infer that
an arbitrary `-f other.yaml` file is Compose. Apply the same predicate to
individual-file targets and snapshot paths. Exclude recognized Compose files
from Checkov's eligible set so Checkov does not report false coverage or
`not_confirmed_by_tool` for them. Checkov currently runs `--directory` on the
entire snapshot, so its adapter must also copy only its verified, non-Compose
eligible files into a private filtered staging tree, preserving relative paths.
Run Checkov on that tree and validate its report paths against the staged root;
include the bounded copy in Checkov's timeout. A candidate filter alone is
insufficient. The new Compose adapter reports its own eligibility.

Read only the bounded, verified UTF-8 snapshot. Never invoke Docker, Compose,
shells, file includes, environment interpolation or network fetches. In
particular, do not run `docker compose config`: Docker's
[Compose trust model](https://docs.docker.com/compose/trust-model/) says even
configuration loading can read host files outside the project. Do not open
`env_file`, `label_file`, `secrets`, `configs`, `include`, `extends`, build
contexts or bind-mount sources. Paths are parsed as text only. No member API
endpoint accepts a Docker image in this phase.

## Bounded YAML interpretation

Declare PyYAML as a direct, locked application dependency. Use its safe node
composer rather than arbitrary-object construction. Enforce the existing
`ScanLimits` snapshot bounds and independent adapter bounds of 1 MiB per
Compose file, 20 MiB total, at most 500 candidate files, 10,000 YAML nodes
per file, 64 nesting levels, 2,000 findings total and the shared scan
deadline. Reject duplicate mapping keys, custom tags, multiple YAML
documents, cyclic aliases and merge keys. For this initial policy version,
any anchor/alias use is treated as unresolved; do not ignore an inherited
security setting and then claim a complete scan. Unsupported syntax marks
that file `partial` with a stable reason and no claim of full coverage.

Require a top-level `services` mapping with mapping-valued services. Walk only
explicit service fields. Keep scalar type and quoting information; match
literal values only. An inspected policy field containing `${...}` or another
unresolved value causes `partial`, not a pass or a guessed finding. Top-level
`include` and service `extends` also cause `partial` because the effective
configuration may be different. Still emit any independently confirmed
literal findings in the same file. Do not combine override files or assume
that a declared service is active; findings describe declared settings only.
If a snapshot contains multiple recognized Compose files in the same
directory, report `effective_config_not_resolved` and `partial`: an override
can remove or replace a setting in the base file. Files in different
directories are separate potential projects and do not cause this warning
solely by coexisting. An explicit `docker compose -f` can still combine files
across directories; without the invocation the scanner cannot infer that.
Fixed finding text says the risky setting
is declared and may be overridden; it never asserts actual deployment state.
If YAML cannot be parsed or the document is not a supported Compose shape,
record a scoped warning without exposing its contents. File names and source
lines come from validated snapshot paths and YAML node marks.

## Initial high-confidence rules

Every rule examines an explicit service-level setting, not an absent default.
Use stable `COMPOSE/` IDs and the same source-location `Finding` contract as
other configuration engines. `redacted_evidence` and messages are fixed text:
never copy a service name, YAML value, secret or snippet. A deterministic ID
may hash the service identity together with rule, path and line. The table's
severity expresses configuration risk, not proven exploitability.

| Rule ID | Match | Severity |
| --- | --- | --- |
| `COMPOSE/PRIVILEGED` | Literal `privileged: true` | HIGH |
| `COMPOSE/HOST_NETWORK` | Literal `network_mode: host` | MEDIUM |
| `COMPOSE/HOST_PID` | Literal `pid: host` | HIGH |
| `COMPOSE/HOST_IPC` | Literal `ipc: host` | MEDIUM |
| `COMPOSE/CAP_ADD_DANGEROUS` | `cap_add` item `ALL` or `SYS_ADMIN` | HIGH |
| `COMPOSE/UNCONFINED_PROFILE` | `security_opt` item disabling seccomp or AppArmor with `unconfined`, in `option=value` or `option:value` form | HIGH |
| `COMPOSE/DOCKER_SOCKET` | Short or long bind mount whose literal host source is `/var/run/docker.sock` or `/run/docker.sock`, including `:ro` | HIGH |
| `COMPOSE/HOST_ROOT_MOUNT` | Short or long bind mount whose literal host source is `/` | HIGH |
| `COMPOSE/EXPLICIT_ROOT_USER` | Literal `user: root`, `user: "0"`, `user: 0`, `user: "root:<group>"` or `user: "0:<group>"` | MEDIUM |
| `COMPOSE/PROVIDER` | Explicit service `provider` mapping, which can name a host executable when Compose operates | HIGH |

For short mounts, split only an unambiguous POSIX source/target/options form;
for long mounts require `type: bind` and a literal `source`. Do not resolve
symlinks or guess what relative paths point to. A named volume, ordinary
project bind mount, omitted `read_only`, unpinned image tag or nonroot user is
not a finding under this initial policy. `read_only: true`, dropped
capabilities and `no-new-privileges` are useful hardening signals, but their
absence alone is too noisy for this high-precision pass. Dynamic values and
unsupported mount syntax are reported as incomplete coverage instead of
being silently accepted. Docker's [service reference](https://docs.docker.com/reference/compose-file/services/)
defines these fields; its [trust model](https://docs.docker.com/compose/trust-model/)
describes their security effects. Map only reviewed privilege-related rules
to [CWE-250](https://cwe.mitre.org/data/definitions/250.html); leave other
CWE IDs empty until reviewed, and never infer a CVE from a Compose setting.

## Pipeline and report contract

Add `ComposePolicyAdapter.scan_snapshot(root, timeout)` to the existing
deterministic adapter sequence with engine ID `compose-policy`, kind
`configuration` and a fixed policy version. Extend `_eligible_snapshot_files`
and `_execution_record` to recognize it, and label its eligible files
`docker-compose` rather than generic YAML. `eligible_files` contains every
recognized snapshot file. `scanned_files` contains files whose explicit
service fields were parsed and checked; it does not include malformed or
unsupported documents. `checks` lists policy IDs actually evaluated. Return
`completed` only when all eligible Compose files were checked without
unresolved syntax, external references, resource limits or deadline loss.
Otherwise use `partial`, `error` or `not_run` and stable reason codes; preserve
any verified findings. If there are no recognized files, use `skipped` with
`no_eligible_files`. The API, CLI, JSON, Markdown and SARIF already consume
generic `Finding` and `ScanExecution`, so no new endpoint or report type is
needed.

## Verification and portfolio evidence

Write table-driven parser tests for positive and safe controls of every rule,
including short/long mounts, `:ro` Docker socket, flow-style YAML, comments,
quoted values, named volumes and nonroot users. Add negative tests for
duplicate keys, aliases/merge, custom tags, cyclic structures, `${...}`
values, `include`/`extends`, malformed/multi-document YAML, oversized files,
node/depth/finding caps and timeout. Verify exact source line, redacted output,
stable IDs, partial coverage and no file/network/process access. Add pipeline
tests showing Checkov's filtered scan root excludes Compose files and a
separate Compose execution. Add only `completed` vulnerable and normal Compose
examples to the authored multi-engine benchmark and report rule-level TP/FP/FN
plus scan time. Dynamic, malformed and multi-file `partial` cases belong in
unit/integration coverage tests because the benchmark's `--require-complete`
would mark their labels `unscored`. Treat scored numbers as authored regression
evidence, not real-world detection rates. Run an unlabeled public
repository measurement separately and report file coverage and unreviewed
findings without calling them TP/FP.

The changes can be split across agents: (1) parser/policy and focused tests,
(2) pipeline/Checkov coverage integration and tests, (3) benchmark cases and
documentation. Dependency lock and final CI evidence should be coordinated by
the integrator to avoid shared-file conflicts.
