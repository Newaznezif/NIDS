# Cybersecurity Analyst Workbench + NIDS
# Scapy on Linux captures via AF_PACKET sockets, so no libpcap package is needed.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOST=0.0.0.0 \
    FLASK_DEBUG=False

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY Backend ./Backend
COPY Frontend ./Frontend

# Runtime data (SQLite DB, uploads, reports) lives here; mount a volume to persist.
RUN mkdir -p /data

EXPOSE 5000

# Capture requires NET_RAW/NET_ADMIN; grant them via compose (cap_add) or
# `docker run --cap-add=NET_RAW --cap-add=NET_ADMIN --network=host`.
CMD ["python", "-m", "Backend.app"]
