from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from botocore.credentials import Credentials as BotoCredentials
from botocore.credentials import RefreshableCredentials

from relay_dbauth import TOKEN_TTL, new_token

VECTORS = json.loads((Path(__file__).parents[2] / "testvectors" / "tokens.json").read_text())
AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


@pytest.mark.parametrize("vector", VECTORS, ids=[v["name"] for v in VECTORS])
def test_tokens_match_the_shared_vectors(vector: dict[str, Any]) -> None:
    creds = BotoCredentials(vector["accessKeyId"], vector["secretAccessKey"], vector.get("sessionToken"))
    now = datetime.fromisoformat(vector["time"].replace("Z", "+00:00"))
    assert new_token(vector["host"], vector.get("region"), creds, now=now) == vector["token"]


def test_botocore_signer_agrees_on_the_signature() -> None:
    from unittest import mock

    from botocore.auth import SigV4QueryAuth
    from botocore.awsrequest import AWSRequest
    from botocore.compat import urlsplit

    creds = BotoCredentials("AKIDPY", "secret")
    request = AWSRequest(
        method="GET",
        url="https://sts.eu-west-1.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
        headers={"X-Relay-Server-Id": "orders.db.userelay.sh"},
    )
    with mock.patch("botocore.auth.get_current_datetime", return_value=AT):
        SigV4QueryAuth(creds, "sts", "eu-west-1", expires=900).add_auth(request)
    expected = dict(p.split("=") for p in urlsplit(request.url).query.split("&"))["X-Amz-Signature"]
    token = new_token("orders.db.userelay.sh", "eu-west-1", creds, now=AT)
    assert f"X-Amz-Signature={expected}" in token


def test_new_token_defaults_to_the_current_time() -> None:
    token = new_token("Orders.AB1CD.db.userelay.sh", "us-east-1", BotoCredentials("AKIDSTATIC", "secret"))
    assert token.startswith("sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity&")
    assert token.endswith("&X-Relay-Server-Id=orders.ab1cd.db.userelay.sh")
    assert "X-Amz-SignedHeaders=host%3Bx-relay-server-id" in token
    assert "X-Amz-Expires=900" in token


def test_empty_region_is_the_global_endpoint() -> None:
    token = new_token("a.db.userelay.sh", "", BotoCredentials("AKIDPY", "secret"), now=AT)
    assert token.startswith("sts.amazonaws.com/?")
    assert "%2Fus-east-1%2Fsts" in token


def test_non_utc_time_is_converted() -> None:
    plus3 = datetime(2026, 1, 2, 6, 4, 5, tzinfo=timezone(timedelta(hours=3)))
    creds = BotoCredentials("AKIDPY", "secret")
    assert new_token("a.db.userelay.sh", None, creds, now=plus3) == new_token("a.db.userelay.sh", None, creds, now=AT)


@pytest.mark.parametrize(
    ("host", "region", "message"),
    [
        ("orders.db.userelay.sh:5432", None, "without a port"),
        ("", None, "not a database hostname"),
        ("localhost", None, "not a database hostname"),
        ("orders.db.userelay.sh", "us-east", "invalid region"),
        ("orders.db.userelay.sh", "evil.com/x", "invalid region"),
    ],
)
def test_refusals(host: str, region: str | None, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        new_token(host, region, BotoCredentials("AKIDPY", "secret"))


def test_missing_credentials() -> None:
    with pytest.raises(ValueError, match="no AWS credentials"):
        new_token("orders.db.userelay.sh", None, None)


def test_token_ttl() -> None:
    assert timedelta(minutes=15) == TOKEN_TTL


def test_refreshable_credentials_expose_their_expiry() -> None:
    from relay_dbauth._token import resolve

    expiry = datetime.now(timezone.utc) + timedelta(hours=1)
    refreshable = RefreshableCredentials(
        "AK",
        "SK",
        "TK",
        expiry,
        lambda: {"access_key": "AK", "secret_key": "SK", "token": "TK", "expiry_time": expiry.isoformat()},
        "test",
    )
    assert resolve(refreshable).expires == expiry
    assert resolve(BotoCredentials("AK", "SK")).expires is None


def test_naive_expiry_is_taken_as_utc() -> None:
    from relay_dbauth._token import resolve

    class Naive:
        _expiry_time = datetime(2026, 1, 2, 4, 0, 0)

        def get_frozen_credentials(self) -> BotoCredentials:
            return BotoCredentials("AK", "SK")

    assert resolve(Naive()).expires == datetime(2026, 1, 2, 4, 0, 0, tzinfo=timezone.utc)
