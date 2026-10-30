# Bounded active API DAST

## Intent and scope

Add an actual ZAP active probe to the existing disposable API DAST path. Preserve the current passive CLI default and its evidence. Active mode remains a CLI/CI operation against a running Docker test container; member uploads and arbitrary URLs cannot start it.

## Approach

ZAP's packaged API scan runs its API-Minimal active policy when `-S` is absent. A custom `-c` file would switch it to Default Policy and enable all scanners before exclusions, widening the attack. We will use the pinned API-Minimal policy and prove completion with a packaged-scan hook marker written only after `zap_active_scan` returns. The Python subprocess deadline caps the full scan. This gives broader API-oriented active coverage while CI proves one SQL injection rule (40018); it is not a claim that every active rule ran against every route.

An active invocation requires `--active`, a full 64-character Docker container ID, both `io.secragraph.dast.disposable=true` and `io.secragraph.dast.active-permitted=true`, and at least one GET OpenAPI operation explicitly marked `x-secragraph-dast-active: true`. The runner pins the inspected ID for later Docker commands. It uses the existing internal isolated bridge, source-only schema and result sanitization, no raw credential or HTTP bodies in reports, bounded runtime, and cleanup. OpenAPI routes are scan seeds, not a request-time firewall; the disposable target may receive additional paths through redirects or ZAP discovery. The report states this limit.

The active call filters the imported OpenAPI to marked GET routes. Passive mode keeps the existing GET/HEAD/OPTIONS selection. ZAP's active policy can probe additional same-origin paths, including `/` and common metadata paths. Active report parsing omits alerts outside marked seeds and warns that such alerts are not reported; passive parsing retains its strict route rejection. Off-origin or malformed alerts still fail the scan. A run is `completed` only if ZAP exits with a documented completed code, its JSON report parses, and the active-completion hook marker is valid. Missing marker, malformed/off-origin alert, timeout, or cleanup failure yields error or partial coverage. `ScanExecution.checks` distinguishes `openapi-passive` from `openapi-active` and the warning no longer says passive-only for active mode. Finding text is mode-neutral.

## CI proof

Run both modes on the same isolated disposable fixture. Keep the old passive header and authenticated-route proof. Add two marked GET routes using disposable in-memory SQLite: an intentionally interpolated query and a parameterized control. Count mutated query requests. Active evidence requires completed `openapi-active`, a real `ZAP/40018` alert with `CWE-89` on the vulnerable route, no `ZAP/40018` on the control, and mutated requests on both. Generate separate normalized active JSON, Markdown, and SARIF; publish neither raw ZAP output nor token. No artifact is published if either scan or the network-isolation probe fails.

The fixture is intentionally vulnerable and excluded from CodeQL's product self-scan. The CI result is evidence for this synthetic API only. Active scanning can change target state, so an operator must use a disposable target and explicitly opt in; the second label and route annotations are authorization checks, not guarantees against target mislabeling by a Docker administrator.

## Verification

Test refusal before ZAP for missing labels, short/reused names, absent route annotation, malformed schema, and unsupported method. Test active command and marker handling, timeout/cleanup, redaction, parser mode text, CLI flag, fixture positive/control behavior, and CI evidence gate. Run Linux CI's live ZAP job and inspect normalized active artifact before merging.
