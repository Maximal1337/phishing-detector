# The web app image. Base pinned by digest: the newest python:3.13 slim build that was
# at least 7 days old when chosen (README, "Security"); stage 7's ECR scan may move it.
FROM python:3.13.17-slim@sha256:d98cc29d3266e535dd9da1099688d9cb3ca4753813571e071763d17725460962

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
