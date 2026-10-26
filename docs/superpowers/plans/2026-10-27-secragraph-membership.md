# SecRAGraph Membership Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add local member login and per-member report isolation without making a shared API token necessary for web users.

**Architecture:** FastAPI accepts optional operator Bearer credentials and opaque, database-backed member sessions as separate principals. A membership service owns password verification and session policy; repositories persist user/session state and enforce scan ownership. Streamlit holds a member session server-side and never receives the operator token.

**Tech Stack:** Python 3.11, FastAPI/Starlette, SQLAlchemy/PostgreSQL/Alembic, hashlib.scrypt, Streamlit, pytest, Docker Compose.

**Spec:** `docs/superpowers/specs/2026-10-27-membership-scanner-rag-design.md`

## Global Constraints

- Local-first only; Compose host ports remain bound to `127.0.0.1` and no public deployment is added.
- Production `/v1` never becomes anonymous; `SECRAGRAPH_API_TOKEN` is optional operator automation auth, never a member identity and never passed to Streamlit.
- Username is 3–32 ASCII characters; password is 12–1024 UTF-8 bytes, versioned scrypt `N=2^15, r=8, p=3`, random salt, and constant-time verification.
- Member session secrets have 256 bits of randomness, only SHA-256 digests at rest, eight-hour absolute and 30-minute idle expiry, and logout revocation.
- Five failed existing-account logins lock for 15 minutes; generic login failures and dummy hashing for unknown names; CLI `unlock-user` restores access.
- User-owned report reads return indistinguishable 404 for missing and other-user IDs; legacy null-owner reports are operator-only.
- Early ASGI authorization precedes multipart body buffering; never log or expose password/session/operator/provider secrets.

## Review Focus

1. Duplicate or malformed Authorization headers: the gate rejects them before any upload read (Task 3 test).
2. Session expiry between login and report download: both JSON and SARIF return 401, not an unscoped report (Task 4 test).
3. Unknown username and wrong password: indistinguishable message and dummy verifier work (Task 1 test).
4. Database race on repeated failed logins: account counter and lockout update atomically under row lock (Task 2 test).
5. Member A's UUID for member B's report: JSON, Markdown, and SARIF all return 404 (Task 4 test).

---

### Task 1: Password policy and pure membership service

**Files:**
- Create: `src/security_review/membership/passwords.py`, `src/security_review/membership/service.py`, `src/security_review/membership/__init__.py`
- Create: `tests/unit/membership/test_passwords.py`, `tests/unit/membership/test_service.py`

**Interfaces:**
- Produce `hash_password(password: str) -> str` and `verify_password(password: str, encoded: str) -> bool`, with a fixed dummy verifier for missing users and no exception text containing user input.
- Produce immutable `MemberIdentity(user_id: UUID, username: str)` and `LoginResult(token: str, identity: MemberIdentity, expires_at: datetime)`.
- Produce `MembershipService(repository: MembershipRepository)` with `register(username, password)`, `login(username, password, now=None)`, `resolve(token, now=None)`, `logout(token)`, `disable(username)`, `unlock(username)`; expose typed `MembershipError(code)`.
- Produce `MembershipRepository` protocol and lock-protected `InMemoryMembershipRepository` for tests. Its `authenticate` operation must update failure count and create a session only through the service after successful verification.

- [ ] **Step 1: Write tests** for username normalization, invalid lengths, Unicode password, no plaintext verifier, valid/invalid and malformed versioned scrypt hashes, generic missing-user/wrong-password behavior, five-attempt lock, 15-minute unlock, 8-hour/30-minute expiry, revoke, disabled user, and fixed-clock determinism.
- [ ] **Step 2: Run tests red:** `.\.venv\Scripts\python.exe -m pytest -q tests/unit/membership`; expect failures for the new interfaces.
- [ ] **Step 3: Implement** the narrow service and in-memory repository; keep token values out of `repr` and exceptions. Use `secrets.token_urlsafe(32)` and `sha256(token.encode())` for session lookup, and `hmac.compare_digest` for password verifier comparison.
- [ ] **Step 4: Run tests green:** `.\.venv\Scripts\python.exe -m pytest -q tests/unit/membership`.
- [ ] **Step 5: Commit** the service and tests.

### Task 2: PostgreSQL membership state and migration

**Files:**
- Modify: `src/security_review/storage/models.py`, `src/security_review/storage/__init__.py`
- Create: `src/security_review/storage/members.py`
- Create: `migrations/versions/20261027_0005_membership.py`
- Create: `tests/integration/storage/test_membership.py`, `tests/unit/storage/test_membership_migration.py`

**Interfaces:**
- `app.members` contains UUID primary key, unique normalized username, versioned password hash, disabled flag, failed-attempt count, locked-until timestamp, created-at timestamp.
- `app.member_sessions` contains SHA-256 digest primary key, member UUID foreign key with cascade deletion, created-at, last-seen-at, and absolute expiration.
- `app.scan_reports.owner_member_id` is nullable UUID foreign key, indexed. Existing rows remain null.
- `SqlAlchemyMembershipRepository(session_factory)` implements the Task 1 protocol with transactional row locking for login outcomes and session refresh/revocation.

- [ ] **Step 1: Write tests** for migration upgrade/downgrade data preservation, unique username, concurrent wrong-password attempts against PostgreSQL with the exact five-attempt threshold, hashed-only session persistence, disabled account, expired session, and no member access to legacy null-owner reports.
- [ ] **Step 2: Run tests red:** `.\.venv\Scripts\python.exe -m pytest -q tests/unit/storage/test_membership_migration.py tests/integration/storage/test_membership.py`; infrastructure tests may be skipped only when PostgreSQL is unavailable and must later run in Compose.
- [ ] **Step 3: Implement** migration, SQLAlchemy models/repository, and exports; do not include plaintext passwords or session secrets in row models.
- [ ] **Step 4: Run tests green** and run Alembic upgrade plus the concurrent-login test against an isolated PostgreSQL integration database; do not claim race-safe lockout if infrastructure is unavailable.
- [ ] **Step 5: Commit** migration, repository, and tests.

### Task 3: Early API principal gate and auth endpoints

**Files:**
- Modify: `src/security_review/api/auth.py`, `src/security_review/api/app.py`, `src/security_review/api/dependencies.py`, `src/security_review/config.py`
- Create: `src/security_review/api/routes/members.py`
- Modify: `tests/unit/api/test_auth.py`, `tests/unit/api/test_composition.py`
- Create: `tests/unit/api/test_members.py`

**Interfaces:**
- Immutable `Principal(kind: Literal['service','member'], member_id: UUID | None, username: str | None, session_digest: str | None)` is set in ASGI scope state.
- `get_principal(request: Request) -> Principal` returns that state or raises the existing typed unauthorized error.
- `POST /v1/auth/register` accepts username/password only when development self-registration is explicitly enabled; `POST /v1/auth/login` returns token, username, expiry; `GET /v1/auth/me` and `POST /v1/auth/logout` require a member session.
- The gate permits only login/registration unauthenticated; `Authorization: Bearer` is operator-only, `Authorization: Session` is member-only. A configured invalid credential never falls back to anonymous development mode.

- [ ] **Step 1: Write tests** for every route's login gate, duplicate header, malformed credential, early rejection of oversized upload, operator/member separation, generic login errors, no-store responses, and production startup without operator token but with membership store.
- [ ] **Step 2: Run tests red:** `.\.venv\Scripts\python.exe -m pytest -q tests/unit/api/test_auth.py tests/unit/api/test_members.py`.
- [ ] **Step 3: Implement** middleware, principal dependency, auth routes, settings, and app composition. Ensure any database failure fails closed without reading upload bodies.
- [ ] **Step 4: Run tests green:** same command plus `tests/unit/api/test_composition.py`.
- [ ] **Step 5: Commit** API auth and tests.

### Task 4: Transactional report ownership and member isolation

**Files:**
- Modify: `src/security_review/ports.py`, `src/security_review/application.py`, `src/security_review/storage/reports.py`, `src/security_review/storage/memory.py`, `src/security_review/storage/models.py`
- Modify: `src/security_review/api/routes/scans.py`, `src/security_review/api/routes/reports.py`
- Modify: `tests/unit/storage/test_reports.py`, `tests/unit/api/test_scan_endpoints.py`, `tests/unit/api/test_report_endpoints.py`
- Create: `tests/integration/api/test_member_isolation.py`

**Interfaces:**
- `ReportRepository.save(report: ScanReport, *, owner_member_id: UUID | None = None) -> None` writes report and owner in one transaction.
- `ReportRepository.get(scan_id: UUID, *, owner_member_id: UUID | None = None) -> ScanReport | None` filters by owner when supplied; `None` is operator-only unscoped access.
- `ScanService.scan(..., owner_member_id: UUID | None = None)` passes ownership to repository. API routes derive owner from `Principal`, not user input.

- [ ] **Step 1: Write tests** showing member A cannot read member B's JSON/Markdown/SARIF, missing and foreign IDs produce same 404, expired sessions produce 401, service token sees legacy reports, and member-created scans persist ownership.
- [ ] **Step 2: Run tests red:** `.\.venv\Scripts\python.exe -m pytest -q tests/unit/api/test_scan_endpoints.py tests/unit/api/test_report_endpoints.py tests/integration/api/test_member_isolation.py`.
- [ ] **Step 3: Implement** owner-aware repository calls and routes; keep the public `ScanReport` JSON schema unchanged and do not let clients choose an owner.
- [ ] **Step 4: Run tests green** including storage and CLI regression tests.
- [ ] **Step 5: Commit** ownership and tests.

### Task 5: Local web and operating contract

**Files:**
- Modify: `src/security_review/cli.py`, `apps/web/client.py`, `apps/web/streamlit_app.py`, `compose.yaml`, `.env.example`, `README.md`, `docs/operations.md`, `docs/architecture.md`, `docs/threat-model.md`
- Modify: `tests/unit/web/test_streamlit_client.py`, `tests/integration/test_compose_contract.py`, `tests/integration/container/test_runtime.py`
- Create: `tests/unit/web/test_membership_ui.py`, `tests/e2e/test_member_cli.py`

**Interfaces:**
- `SecRAGraphApiClient` gains `register`, `login`, `me`, `logout` and a member-session credential mode; its existing explicit operator token mode remains for automation tests.
- Streamlit stores only the member session in server-side `st.session_state`, never reads `SECRAGRAPH_API_TOKEN`, and clears it on logout or 401.
- Compose no longer requires `SECRAGRAPH_API_TOKEN` to start the API and does not pass it to `web`. The CLI offers password-hidden account creation and recovery.

- [ ] **Step 1: Write tests** for no operator token in web config, login flow, logout and expired-token clearing, bounded credential errors, CLI hidden-password prompts, and tokenless Compose contracts.
- [ ] **Step 2: Run tests red:** `.\.venv\Scripts\python.exe -m pytest -q tests/unit/web tests/e2e/test_member_cli.py tests/integration/test_compose_contract.py`.
- [ ] **Step 3: Implement** the UI/client, `src/security_review/cli.py` account commands wired to the membership repository with hidden and confirmed password prompts, Compose and documentation changes; no default password or demo session secret is committed.
- [ ] **Step 4: Run tests green**, Ruff, mypy, Bandit, full pytest, and authenticated Compose smoke in an isolated project.
- [ ] **Step 5: Commit** the integrated membership delivery.
