# syntax=docker/dockerfile:1.7

# Rebuild the released Gitleaks source with a patched, checksum-verified Go
# module graph. This is a SecRAGraph-derived binary, not the upstream asset.
FROM --platform=$BUILDPLATFORM golang:1.27.4-trixie@sha256:b54b2639de8c1bfe538ec5ffc45f29b1932235ac5f6d63c059853646677112d9 AS gitleaks-builder

ARG TARGETOS
ARG TARGETARCH
ENV GOTOOLCHAIN=local \
    GOPROXY=https://proxy.golang.org \
    GOSUMDB=sum.golang.org
WORKDIR /src
RUN git clone --depth 1 --branch v8.30.1 https://github.com/gitleaks/gitleaks.git . \
    && test "$(git rev-parse HEAD)" = "83d9cd684c87d95d656c1458ef04895a7f1cbd8e"
COPY infra/scanners/gitleaks/go.mod infra/scanners/gitleaks/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download \
    && go mod verify \
    && CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
       go build -mod=readonly -trimpath -tags=gore2regex \
       -ldflags='-s -w -X=github.com/zricethezav/gitleaks/v8/version.Version=8.30.1' \
       -o /out/gitleaks ./main.go

# Official Python 3.11.18 slim Trixie multi-platform index, verified on 2026-11-16.
FROM python:3.11-slim-trixie@sha256:07d4824036af339fa1b6ef769cc99d9c10a141769538b52b3b597c84f7a7b535 AS builder

COPY --from=ghcr.io/astral-sh/uv:0.12.23@sha256:61d393e44e249f2e4b526b6c7ddcecce245946826e608e11c93ad4f5bba55b21 /uv /uvx /bin/
ENV UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0
WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project --no-editable

COPY src ./src
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable

COPY infra/scanners/checkov-requirements.txt /tmp/checkov-requirements.txt
RUN uv venv /opt/checkov-venv \
    && uv pip sync --python /opt/checkov-venv/bin/python --require-hashes --strict /tmp/checkov-requirements.txt

ARG TARGETARCH
COPY infra/scanners/install_tools.py /tmp/install_scanner_tools.py
RUN python /tmp/install_scanner_tools.py /opt/scanners "${TARGETARCH}" --opengrep-only
COPY --from=gitleaks-builder /out/gitleaks /opt/scanners/gitleaks


FROM python:3.11-slim-trixie@sha256:07d4824036af339fa1b6ef769cc99d9c10a141769538b52b3b597c84f7a7b535 AS runtime

# Debian's security repository fixes both zlib advisories in the pinned base.
# Runtime commands use the copied virtual environments. The mount command is
# unnecessary inside the non-root service container; keep protected login and
# essential util-linux packages intact.
RUN apt-get update \
    && apt-get install -y --no-install-recommends zlib1g=1:1.3.dfsg+really1.3.1-1+deb13u1 \
    && apt-get purge -y mount \
    && rm -rf /var/lib/apt/lists/* /usr/local/lib/python3.11/site-packages

ENV PATH="/opt/scanners:/opt/checkov-venv/bin:/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TMPDIR=/tmp/secragraph \
    SECRAGRAPH_SNAPSHOT_TMPDIR=/tmp/secragraph-snapshots \
    HOME=/tmp/secragraph \
    XDG_CACHE_HOME=/tmp/secragraph/.cache
WORKDIR /app

RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app \
    && mkdir -p /tmp/secragraph /tmp/secragraph-snapshots \
    && chown app:app /tmp/secragraph /tmp/secragraph-snapshots

COPY --from=builder --chown=app:app /app/.venv /app/.venv
COPY --from=builder --chown=app:app /opt/checkov-venv /opt/checkov-venv
COPY --from=builder --chown=app:app /opt/scanners /opt/scanners
COPY --chown=app:app apps ./apps
COPY --chown=app:app data ./data
COPY --chown=app:app migrations ./migrations
COPY --chown=app:app alembic.ini ./alembic.ini

USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
    CMD ["/app/.venv/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=2).read()"]

CMD ["/app/.venv/bin/uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
