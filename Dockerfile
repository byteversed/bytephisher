FROM python:3.11-slim

LABEL org.opencontainers.image.title="BytePhisher" \
      org.opencontainers.image.description="Advanced phishing-simulation framework (authorized engagements)" \
      org.opencontainers.image.version="1.0"

WORKDIR /app

# ssh is needed by the localhost.run / serveo / hoplink tunnelers; curl for
# health checks. cloudflared is fetched at runtime into ./bin if absent.
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-client curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN python3 tools/gen_templates.py

EXPOSE 8080 8090
VOLUME ["/app/data"]

# Default: local-only mode so nothing is exposed until you pass -t/--tunneler.
ENTRYPOINT ["python3", "bytephisher.py"]
CMD ["-o", "google", "-m", "test", "-p", "8080", "--no-tui"]
