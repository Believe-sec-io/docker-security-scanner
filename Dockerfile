# Hardened build of the scanner itself. The tool scans this file in CI.
FROM python:3.12.7-slim-bookworm AS builder

WORKDIR /build

COPY requirements.txt /build/requirements.txt
RUN pip install --no-cache-dir --target /build/site-packages -r /build/requirements.txt


FROM python:3.12.7-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/site-packages \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY --from=builder /build/site-packages /opt/site-packages
COPY main.py /app/main.py
COPY src /app/src
COPY examples /app/examples

RUN adduser --system --uid 10001 --group dss \
    && chown -R dss:dss /app

USER 10001

HEALTHCHECK --interval=1h --timeout=30s --retries=1 \
    CMD ["python", "-m", "src.cli", "--version"]

ENTRYPOINT ["python", "-m", "src.cli"]
CMD ["/app/examples", "--format", "console", "--no-color"]
