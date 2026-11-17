from __future__ import annotations

import hashlib
import hmac
import re
from datetime import datetime, timedelta, timezone
from typing import Any, NamedTuple, Protocol
from urllib.parse import quote

TOKEN_TTL = timedelta(minutes=15)

_SERVER_ID_HEADER = "X-Relay-Server-Id"
_STS_VERSION = "2011-06-15"
_GLOBAL_HOST = "sts.amazonaws.com"
_GLOBAL_REGION = "us-east-1"
_AWS_REGION = re.compile(r"^[a-z]{2}(-[a-z]+)+-[0-9]$")
_DB_HOST = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
_EMPTY_PAYLOAD_HASH = hashlib.sha256(b"").hexdigest()


class _Frozen(Protocol):
    access_key: str
    secret_key: str
    token: str | None


class Credentials(Protocol):
    """AWS credentials, such as botocore.credentials.Credentials or boto3.Session().get_credentials()."""

    def get_frozen_credentials(self) -> _Frozen: ...


class Resolved(NamedTuple):
    access_key: str
    secret_key: str
    token: str | None
    expires: datetime | None


def resolve(credentials: Credentials | None) -> Resolved:
    if credentials is None:
        raise ValueError("relay_dbauth: no AWS credentials")
    frozen = credentials.get_frozen_credentials()
    expires: Any = getattr(credentials, "_expiry_time", None)
    if not isinstance(expires, datetime):
        expires = None
    elif expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return Resolved(frozen.access_key, frozen.secret_key, frozen.token or None, expires)


def _quote(value: str) -> str:
    return quote(value, safe="-_.~")


def _hmac(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode(), hashlib.sha256).digest()


def _regional_host(region: str) -> str:
    suffix = "amazonaws.com.cn" if region.startswith("cn-") else "amazonaws.com"
    return f"sts.{region}.{suffix}"


def sign(resolved: Resolved, host: str, region: str | None, now: datetime) -> str:
    host = host.lower()
    if not _DB_HOST.match(host):
        raise ValueError(f"relay_dbauth: {host!r} is not a database hostname; pass the host without a port")
    sts_host, signing_region = _GLOBAL_HOST, _GLOBAL_REGION
    if region:
        if not _AWS_REGION.match(region):
            raise ValueError(f"relay_dbauth: invalid region {region!r}")
        sts_host, signing_region = _regional_host(region), region

    moment = now.astimezone(timezone.utc)
    date = moment.strftime("%Y%m%d")
    stamp = moment.strftime("%Y%m%dT%H%M%SZ")
    scope = f"{date}/{signing_region}/sts/aws4_request"
    params = {
        "Action": "GetCallerIdentity",
        "Version": _STS_VERSION,
        "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
        "X-Amz-Credential": f"{resolved.access_key}/{scope}",
        "X-Amz-Date": stamp,
        "X-Amz-Expires": str(int(TOKEN_TTL.total_seconds())),
        "X-Amz-SignedHeaders": "host;x-relay-server-id",
    }
    if resolved.token:
        params["X-Amz-Security-Token"] = resolved.token
    query = "&".join(f"{_quote(k)}={_quote(v)}" for k, v in sorted(params.items()))
    canonical = "\n".join(
        [
            "GET",
            "/",
            query,
            f"host:{sts_host}\nx-relay-server-id:{host}\n",
            "host;x-relay-server-id",
            _EMPTY_PAYLOAD_HASH,
        ]
    )
    string_to_sign = "\n".join(["AWS4-HMAC-SHA256", stamp, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    key = _hmac(("AWS4" + resolved.secret_key).encode(), date)
    for part in (signing_region, "sts", "aws4_request"):
        key = _hmac(key, part)
    signature = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    return f"{sts_host}/?{query}&X-Amz-Signature={signature}&{_SERVER_ID_HEADER}={_quote(host)}"


def new_token(
    host: str,
    region: str | None,
    credentials: Credentials | None,
    *,
    now: datetime | None = None,
) -> str:
    """Return a token for the database at host, signed through the STS endpoint of region (None for the global one)."""
    return sign(resolve(credentials), host, region, now or datetime.now(timezone.utc))
