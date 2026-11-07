"""gunicorn settings for the container: gunicorn --config python:webapp.gunicorn_conf "webapp:create_app()".

Setting names as documented for the pinned gunicorn 26.2.0 (gunicorn/config.py, "Server Socket",
"Worker Processes", "Control" and "Logging" sections).
"""

import json
import logging

bind = "0.0.0.0:8000"
workers = 2
# Threads: a scan mostly waits on PostgreSQL and Valkey, so 4 threads per worker serve requests while
# others wait. Each worker's connection pool holds up to 4 connections (webapp.credentials.POOL_SIZE).
worker_class = "gthread"
threads = 4
# Keep idle connections from the load balancer open longer than its 60 s idle timeout, so the ALB
# always closes them first; otherwise it may send a request on a connection gunicorn is closing (502).
keepalive = 75
worker_tmp_dir = "/tmp"  # worker heartbeat files; the root filesystem is read-only

# The control socket (since 25.1.0, for the gunicornc tool) isn't used: systemd and the Auto Scaling
# group restart the app. Off, which also stops gunicorn trying to create ~/.gunicorn on a read-only disk.
control_socket_disable = True

accesslog = None  # the app writes its own JSON line per request


def worker_exit(server, worker) -> None:
    """Server hook, run in the worker process as it exits: close its PostgreSQL pool cleanly."""
    from webapp.credentials import close_pools

    close_pools()


class JsonFormatter(logging.Formatter):
    """gunicorn's own log lines (start, workers, signals, errors) as JSON, like the app's lines."""

    def format(self, record: logging.LogRecord) -> str:
        line = {"event": "gunicorn", "level": record.levelname.lower(), "message": record.getMessage()}
        if record.exc_info and record.exc_info[0]:
            line["error"] = record.exc_info[0].__name__  # the class only, as in the app's failure events
        return json.dumps(line)


logconfig_dict = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"json": {"()": "webapp.gunicorn_conf.JsonFormatter"}},
    "handlers": {"stdout": {"class": "logging.StreamHandler", "formatter": "json", "stream": "ext://sys.stdout"}},
    "loggers": {"gunicorn.error": {"level": "INFO", "handlers": ["stdout"], "propagate": False}},
    "root": {"level": "WARNING", "handlers": ["stdout"]},
}
