FROM python:3.12-slim

WORKDIR /app

# Install libsodium (required by pynacl)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsodium23 && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

ENV DB_PATH=/data/peer2pear_relay.db
VOLUME /data

EXPOSE 8443

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8443"]
