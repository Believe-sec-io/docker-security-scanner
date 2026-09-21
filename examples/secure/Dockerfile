# Exemple durci - bonnes pratiques appliquees.
# Il ne devrait produire aucun constat HIGH/CRITICAL.
FROM python:3.12-slim AS builder

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim

LABEL org.opencontainers.image.title="exemple-securise" \
      org.opencontainers.image.source="https://github.com/Believe-sec-io/docker-security-scanner" \
      org.opencontainers.image.licenses="MIT" \
      maintainer="Believe07"

RUN useradd --create-home --uid 10001 appuser

WORKDIR /app

COPY --from=builder /install /usr/local
COPY --chown=appuser:appuser app.py .

USER 10001:10001

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health').read()" || exit 1

ENTRYPOINT ["python", "app.py"]
