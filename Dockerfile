# Standalone EZ2ON private server — no mitmproxy.
#
#   docker compose build
#   docker compose up -d
#
# The image is just the Python code; all personal/served data is mounted:
#   ./server/data        -> /app/server/data        (rw: RSA key, templates, store.db)
#   ./extracted_charts   -> /app/extracted_charts   (ro: chart/keysound ciphertext)
# See server/README.md ("Docker") for the full guide.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /app

COPY server/requirements.txt server/requirements.txt
RUN pip install --no-cache-dir -r server/requirements.txt

# server code + the repo-root chart decryptor _pserver imports lazily
COPY server/ server/
COPY decrypt_chart.py decrypt_chart.py

# mount points (bind mounts overlay these); the archive is not baked in
RUN mkdir -p /app/extracted_charts /app/server/data

# Runs as root by default so a plain `docker run` can write the bind mounts;
# compose overrides `user:` to the host uid:gid (recommended).  To run the image
# standalone as non-root instead, `chown -R 10001 server/data` first and set
# `USER 10001` here.
EXPOSE 8081
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD \
    python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8081/healthz',timeout=4).read()==b'ok' else 1)"

ENTRYPOINT ["python", "server/app.py", "--host", "0.0.0.0", "--port", "8081"]
