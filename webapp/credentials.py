"""Credentials from AWS Secrets Manager (in AWS) or environment variables (locally).

Secret values are read inside the process and never logged or printed.
"""

from __future__ import annotations

import json
import os
import time
from typing import Callable

CACHE_SECONDS = 300  # re-read a secret every 5 minutes, so a rotated value is picked up


class CachedSecret:
    """A JSON secret from Secrets Manager, cached for CACHE_SECONDS."""

    def __init__(self, secret_id: str, fetch: Callable[[str], str] | None = None) -> None:
        self._secret_id = secret_id
        self._fetch = fetch or _secrets_manager_fetch
        self._value: dict | None = None
        self._read_at = 0.0

    def get(self) -> dict:
        if self._value is None or time.monotonic() - self._read_at > CACHE_SECONDS:
            self._value = json.loads(self._fetch(self._secret_id))
            self._read_at = time.monotonic()
        return self._value

    def forget(self) -> None:
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


def database_connect() -> Callable | None:
    """A function opening a new database connection, or None when no database is configured."""
    host = os.environ.get("DB_HOST")
    if not host:
        return None
    import psycopg

    options = {
        "host": host,
        "port": int(os.environ.get("DB_PORT", "5432")),
        "dbname": os.environ.get("DB_NAME", "phishdet"),
        "sslmode": os.environ.get("DB_SSLMODE", "prefer"),
        "connect_timeout": 3,
    }
    if secret_id := os.environ.get("DB_SECRET_ARN"):  # the RDS-managed master secret, rotated by RDS
        secret = CachedSecret(secret_id)

        def connect():
            try:
                return psycopg.connect(user=secret.get()["username"], password=secret.get()["password"], **options)
            except psycopg.OperationalError:
                secret.forget()  # the password may have been rotated: read it again next time
                raise

        return connect
    user, password = os.environ.get("DB_USER", ""), os.environ.get("DB_PASSWORD", "")
    return lambda: psycopg.connect(user=user, password=password, **options)
