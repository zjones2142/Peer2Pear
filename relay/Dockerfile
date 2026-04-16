FROM python:3.12-slim

WORKDIR /app

# Install libsodium (required by pynacl) and curl (for healthcheck).
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsodium23 curl && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

ENV DB_PATH=/data/peer2pear_relay.db
VOLUME /data

EXPOSE 8443

# Parity fix: same HEALTHCHECK config as the Go image so both flavours
# surface container health identically to orchestrators.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8443/healthz || exit 1

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8443"]
