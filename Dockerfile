# One shared image for every Python service (devices, ingest, detector, api,
# attacker, tests). The attacker and the devices therefore run byte-identical
# MQTT/TLS client code, so the IDS cannot separate them by client fingerprint.
FROM python@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
# ^ python:3.12-slim, pinned by digest for reproducible builds

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app \
    PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1

COPY requirements.txt /tmp/requirements.txt
# Fail the build (not the runtime) if the lock is empty or a core library is missing.
RUN test -s /tmp/requirements.txt \
 && pip install --root-user-action=ignore -r /tmp/requirements.txt \
 && python -c "import paho.mqtt, pymongo, fastapi, sklearn, dpkt"

# Run as the host user's uid so mounted 0600 certs stay readable without loosening them.
ARG APP_UID=1000
ARG APP_GID=1000
RUN groupadd -g ${APP_GID} app && useradd -u ${APP_UID} -g ${APP_GID} -M -s /usr/sbin/nologin app

WORKDIR /app
COPY services/ services/
COPY ids/ ids/
COPY tests/ tests/
COPY scripts/__init__.py scripts/*.py scripts/
# Committed results data served read-only by GET /results/summary.
COPY docs/results/ docs/results/
USER app
