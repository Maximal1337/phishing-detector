"""DatabasePool without a database: one pool per process, reuse, fork safety, reset on a failure."""

import os
from contextlib import contextmanager

import psycopg
import psycopg_pool
import pytest

from webapp.credentials import DatabasePool


class FakePool:
    created: list = []

    def __init__(self, **kwargs):
        self.kwargs, self.closed, self.fail = kwargs, False, False
        FakePool.created.append(self)

    @staticmethod
    def check_connection(conn):
        pass

    @contextmanager
    def connection(self):
        if self.fail:
            raise psycopg.OperationalError("server closed the connection unexpectedly")
        yield ("connection of", id(self))

    def close(self, timeout=None):
        self.closed = True


@pytest.fixture(autouse=True)
def fake_pool(monkeypatch):
    FakePool.created = []
    monkeypatch.setattr(psycopg_pool, "ConnectionPool", FakePool)


def test_one_small_pool_is_opened_lazily_and_reused():
    pool = DatabasePool({"host": "db"}, lambda: ("app", "secret"))
    assert FakePool.created == []  # nothing at construction (before gunicorn forks)
    with pool.connection() as first:
        pass
    with pool.connection() as second:
        pass
    assert len(FakePool.created) == 1 and first == second
    settings = FakePool.created[0].kwargs
    assert (settings["min_size"], settings["max_size"], settings["kwargs"]["user"]) == (1, 2, "app")
    assert settings["check"] is FakePool.check_connection


def test_a_forked_worker_opens_its_own_pool(monkeypatch):
    pool = DatabasePool({"host": "db"})
    with pool.connection():
        pass
    monkeypatch.setattr(os, "getpid", lambda: 999_999)
    with pool.connection():
        pass
    assert len(FakePool.created) == 2
    assert not FakePool.created[0].closed  # the parent's pool is dropped, not closed, in the child


def test_a_dropped_connection_resets_the_pool_and_the_secret():
    forgotten = []
    pool = DatabasePool({"host": "db"}, lambda: ("app", "secret"), forget=lambda: forgotten.append(True))
    with pool.connection():
        pass
    FakePool.created[0].fail = True
    with pytest.raises(psycopg.OperationalError):
        with pool.connection():
            pass
    assert FakePool.created[0].closed and forgotten == [True]
    with pool.connection():  # the next call opens a fresh pool
        pass
    assert len(FakePool.created) == 2
