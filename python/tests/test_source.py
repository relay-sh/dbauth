from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

import pytest
from botocore.credentials import Credentials as BotoCredentials

from relay_dbauth import REFRESH_BEFORE, TOKEN_TTL, TokenSource, new_token

AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
HOST = "orders.ab1cd.db.userelay.sh"


class Clock:
    def __init__(self) -> None:
        self.now = AT

    def __call__(self) -> datetime:
        return self.now


class Counting:
    def __init__(self, expiry: datetime | None = None) -> None:
        self.calls = 0
        self._expiry_time = expiry

    def get_frozen_credentials(self) -> BotoCredentials:
        self.calls += 1
        return BotoCredentials(f"AKIDPY{self.calls}", "secret")


def test_refresh_before() -> None:
    assert timedelta(minutes=2) == REFRESH_BEFORE


def test_token_is_cached_until_shortly_before_expiry() -> None:
    clock, creds = Clock(), Counting()
    source = TokenSource(HOST, "us-east-1", creds, clock=clock)
    first = source.token()
    assert first == new_token(HOST, "us-east-1", BotoCredentials("AKIDPY1", "secret"), now=AT)
    clock.now = AT + TOKEN_TTL - REFRESH_BEFORE - timedelta(seconds=1)
    assert source.token() == first
    assert creds.calls == 1
    clock.now = AT + TOKEN_TTL - REFRESH_BEFORE
    second = source.token()
    assert second != first
    assert creds.calls == 2


def test_credential_expiry_shortens_the_cache() -> None:
    clock, creds = Clock(), Counting(expiry=AT + timedelta(minutes=5))
    source = TokenSource(HOST, None, creds, clock=clock)
    source.token()
    clock.now = AT + timedelta(minutes=3)
    source.token()
    assert creds.calls == 2


def test_later_credential_expiry_does_not_extend_the_cache() -> None:
    clock, creds = Clock(), Counting(expiry=AT + timedelta(hours=1))
    source = TokenSource(HOST, None, creds, clock=clock)
    source.token()
    clock.now = AT + timedelta(minutes=14)
    source.token()
    assert creds.calls == 2


def test_failures_are_not_cached() -> None:
    source = TokenSource("localhost", None, Counting(), clock=Clock())
    with pytest.raises(ValueError, match="not a database hostname"):
        source.token()
    with pytest.raises(ValueError, match="not a database hostname"):
        source.token()


def test_missing_credentials() -> None:
    with pytest.raises(ValueError, match="no AWS credentials"):
        TokenSource(HOST, None, None).token()


def test_default_clock_and_concurrent_use() -> None:
    creds = Counting()
    source = TokenSource(HOST, "eu-west-1", creds)
    results: list[str] = []
    threads = [threading.Thread(target=lambda: results.append(source.token())) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(set(results)) == 1
    assert creds.calls == 1
