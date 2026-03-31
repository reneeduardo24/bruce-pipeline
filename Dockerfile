FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    APT_LISTCHANGES_FRONTEND=none

RUN apt-get update \
    && apt-get install -y --no-install-recommends tshark ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY analyzer /app/analyzer
COPY config /app/config
COPY hooks /app/hooks

RUN chmod +x /app/hooks/on_state_change.sh

VOLUME ["/data"]

CMD ["python", "-m", "analyzer.app", "run"]
