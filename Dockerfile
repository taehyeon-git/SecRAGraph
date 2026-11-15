# syntax=docker/dockerfile:1.7

# Official Python 3.11.18 slim Trixie multi-platform index, verified on 2026-11-16.
FROM python:3.15-slim-trixie@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS builder

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
RUN python /tmp/install_scanner_tools.py /opt/scanners "${TARGETARCH}"


FROM python:3.15-slim-trixie@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS runtime

# Debian's security repository fixes both zlib advisories in the pinned base.
# Runtime commands use the copied virtual environments; remove unused global
# packaging tools so they are not shipped in the final image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends zlib1g=1:1.3.dfsg+really1.3.1-1+deb13u1 \
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
