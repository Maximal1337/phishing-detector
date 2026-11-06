# The web app image. Base pinned by digest. 3.13.18-slim was a day old when chosen: the
# 7-day rule gives way when a newer base fixes HIGH or CRITICAL scan findings (README, "Security").
FROM python:3.13.18-slim@sha256:09a17cad02668ae61ece136b4fd36ac3849e14f670ebedb637ea3e15580525bc

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Every package, transitive ones included, pinned with hashes; wheels only, nothing is built.
COPY requirements.lock .
RUN pip install --no-cache-dir --require-hashes --only-binary :all: -r requirements.lock

COPY phishing_detector/ phishing_detector/
COPY webapp/ webapp/

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app
USER 10001

ARG APP_VERSION=dev
ENV APP_VERSION=${APP_VERSION}

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import sys, urllib.request; sys.exit(urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status != 200)"]

# Two workers; the worker heartbeat files go to /tmp so the root filesystem can be read-only.
CMD ["gunicorn", "--workers", "2", "--worker-tmp-dir", "/tmp", "--bind", "0.0.0.0:8000", "webapp:create_app()"]
