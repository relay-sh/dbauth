from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone
from typing import Callable

from relay_dbauth._token import TOKEN_TTL, Credentials, resolve, sign

REFRESH_BEFORE = timedelta(minutes=2)


class TokenSource:
    """Caches a token for one database and mints a new one shortly before it expires; thread-safe."""

    def __init__(
        self,
        host: str,
        region: str | None,
        credentials: Credentials | None,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._host = host
        self._region = region
        self._credentials = credentials
        self._clock = clock
        self._lock = threading.Lock()
        self._token = ""
        self._expires = datetime.min.replace(tzinfo=timezone.utc)

    def token(self) -> str:
        """Return the cached token, or mint a new one when it is missing or about to expire."""
        with self._lock:
            now = self._clock()
            if self._token and now < self._expires - REFRESH_BEFORE:
                return self._token
            resolved = resolve(self._credentials)
            token = sign(resolved, self._host, self._region, now)
            expires = now + TOKEN_TTL
            if resolved.expires is not None and resolved.expires < expires:
                expires = resolved.expires
            self._token, self._expires = token, expires
            return token
