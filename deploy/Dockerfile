# API + worker image. Build from the repo root:
#   docker build -f deploy/Dockerfile -t corpsec-api .
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.11.8 /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    PATH=/app/.venv/bin:$PATH \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml uv.lock .python-version ./
COPY packages packages
COPY apps/api apps/api
RUN uv sync --frozen --no-dev --package corpsec-api

RUN useradd --system --uid 10001 corpsec \
    && mkdir -p /data && chown corpsec /data  # intel snapshot volume, written by the worker
USER corpsec
WORKDIR /app/apps/api
EXPOSE 8000
CMD ["uvicorn", "corpsec_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
