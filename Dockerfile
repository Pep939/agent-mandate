# Wire gateway (C1). Local development image — not a hardened production build.
FROM python:3.13-slim

ENV UV_LINK_MODE=copy \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir uv
RUN useradd -m appuser

WORKDIR /app

# Dependencies first (layer cache), then the source. Everything is
# appuser-owned so the venv is writable at runtime.
COPY --chown=appuser:appuser pyproject.toml uv.lock README.md ./
COPY --chown=appuser:appuser src ./src
RUN chown -R appuser:appuser /app
USER appuser
RUN uv sync --frozen --no-dev

# Runtime files: entrypoint script, migrations (alembic runs before start).
COPY --chown=appuser:appuser alembic.ini ./
COPY --chown=appuser:appuser migrations ./migrations
COPY --chown=appuser:appuser scripts ./scripts

EXPOSE 8100

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8100/health', timeout=2)" || exit 1

# Migrate, then serve. The process is restart-safe (C1): state lives in
# Postgres, keys live in the mounted volume, and `build_gateway_state`
# rehydrates the registry on startup.
CMD ["sh", "-c", "uv run alembic upgrade head && exec uv run python scripts/run_gateway.py"]
