"""Credentials from AWS Secrets Manager (in AWS) or environment variables (locally).

Secret values are read inside the process and never logged or printed.
"""

from __future__ import annotations

import json
import os
import threading
import time
from contextlib import contextmanager
from typing import Callable

CACHE_SECONDS = 300  # re-read a secret every 5 minutes, so a rotated value is picked up


class CachedSecret:
    """A JSON secret from Secrets Manager, cached for CACHE_SECONDS. Safe to share between threads:
    one thread refreshes it while the others wait, so an expired secret is fetched once, not per thread."""

    def __init__(self, secret_id: str, fetch: Callable[[str], str] | None = None) -> None:
        self._secret_id = secret_id
        self._fetch = fetch or _secrets_manager_fetch
        self._value: dict | None = None
        self._read_at = 0.0
        self._lock = threading.Lock()

    def get(self) -> dict:
        with self._lock:
            if self._value is None or time.monotonic() - self._read_at > CACHE_SECONDS:
                self._value = json.loads(self._fetch(self._secret_id))
                self._read_at = time.monotonic()
            return self._value

    def forget(self) -> None:
        with self._lock:
            self._value = None


def _secrets_manager_fetch(secret_id: str) -> str:
    import boto3  # only needed in AWS

    client = boto3.client("secretsmanager", region_name=os.environ.get("AWS_REGION"))
    return client.get_secret_value(SecretId=secret_id)["SecretString"]


def basic_auth_credentials() -> Callable[[], tuple[str, str] | None]:
    """A function returning (username, password), or None when auth is off (local runs only)."""
    if secret_id := os.environ.get("AUTH_SECRET_ARN"):
        secret = CachedSecret(secret_id)
        return lambda: (secret.get()["username"], secret.get()["password"])
    user, password = os.environ.get("BASIC_AUTH_USER", ""), os.environ.get("BASIC_AUTH_PASSWORD", "")
    return (lambda: (user, password)) if user and password else (lambda: None)


_POOLS: list["DatabasePool"] = []  # every pool made in this process, for close_pools()


class DatabasePool:
    """A small pool of PostgreSQL connections per worker process, opened on first use.

    gunicorn imports the app and then forks the workers; a connection must never be shared by two
    processes, so the pool is created lazily inside the process that uses it, and again if the
    process id has changed. A failed connection (database down, password rotated) closes the
    pool and forgets the cached secret, so the next call starts fresh; the caller sees the
    psycopg.OperationalError (PoolTimeout is one) and reports the history as unavailable.
    """

    def __init__(
        self,
        options: dict,
        credentials: Callable[[], tuple[str, str]] | None = None,
        forget: Callable[[], None] = lambda: None,
        min_size: int = 1,
        max_size: int = 2,
        timeout: float = 3.0,
    ) -> None:
        self._options, self._credentials, self._forget = options, credentials, forget
        self._min_size, self._max_size, self._timeout = min_size, max_size, timeout
        self._pool = None
        self._pid: int | None = None
        self._lock = threading.Lock()
        _POOLS.append(self)

    def _current(self):
        with self._lock:
            if self._pool is None or self._pid != os.getpid():  # first use, or a forked child
                from psycopg_pool import ConnectionPool

                kwargs = dict(self._options)
                if self._credentials:
                    kwargs["user"], kwargs["password"] = self._credentials()
                self._pool = ConnectionPool(
                    kwargs=kwargs,
                    min_size=self._min_size,
                    max_size=self._max_size,
                    timeout=self._timeout,  # how long a request waits for a connection
                    check=ConnectionPool.check_connection,  # replace connections the server dropped
                    open=True,
                    name="history",
                )
                self._pid = os.getpid()
            return self._pool

    @contextmanager
    def connection(self):
        import psycopg

        try:
            with self._current().connection() as conn:  # commits on success, rolls back on error
                yield conn
        except psycopg.OperationalError:
            self.reset()
            raise

    def reset(self) -> None:
        self.close(timeout=0)
        self._forget()

    def close(self, timeout: float = 2.0) -> None:
        """Close this process's pool and wait up to `timeout` for its threads to stop."""
        with self._lock:
            pool, own = self._pool, self._pid == os.getpid()
            self._pool = None
        if pool is not None and own:  # a pool inherited from the parent process is only dropped
            pool.close(timeout=timeout)


def close_pools(timeout: float = 2.0) -> None:
    """Called by gunicorn's worker_exit hook: an open pool's threads would otherwise be left running at exit,
    and psycopg_pool warns that it couldn't stop them."""
    for pool in _POOLS:
        pool.close(timeout)


POOL_SIZE = 4  # per worker process; at least gunicorn's threads per worker (webapp/gunicorn_conf.py)


def database_connect() -> Callable | None:
    """A function returning a database connection context, or None when no database is configured."""
    host = os.environ.get("DB_HOST")
    if not host:
        return None
    options = {
        "host": host,
        "port": int(os.environ.get("DB_PORT", "5432")),
        "dbname": os.environ.get("DB_NAME", "phishdet"),
        "sslmode": os.environ.get("DB_SSLMODE", "prefer"),
        "connect_timeout": 3,
    }
    if secret_id := os.environ.get("DB_SECRET_ARN"):  # the RDS-managed master secret, rotated by RDS
        secret = CachedSecret(secret_id)
        pool = DatabasePool(options, lambda: (secret.get()["username"], secret.get()["password"]), forget=secret.forget, max_size=POOL_SIZE)
    else:
        user, password = os.environ.get("DB_USER", ""), os.environ.get("DB_PASSWORD", "")
        pool = DatabasePool(options, lambda: (user, password), max_size=POOL_SIZE)
    return pool.connection
