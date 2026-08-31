"""Small HTTP helpers shared by the real source adapters.

Centred on ``requests`` and kept deliberately thin: form POSTs and raw GET
bytes with finite retries and a research user-agent. Rate limit / transient
network failures surface as :class:`HttpFetchError` so the caller can decide
whether a retry makes sense.
"""

from __future__ import annotations

import time

import requests

from .base import SourceError

DEFAULT_TIMEOUT_S = 60
DEFAULT_RETRIES = 2
DEFAULT_BACKOFF_S = 1.5

_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 "
    "FinDroidBD400EducationalResearch/1.0"
)


class HttpFetchError(SourceError):
    """Raised when a real source cannot complete an HTTP exchange."""


def _session(headers: dict[str, str] | None) -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": _USER_AGENT})
    if headers:
        s.headers.update(headers)
    return s


def post_form(
    url: str,
    fields: dict[str, str],
    *,
    headers: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT_S,
    retries: int = DEFAULT_RETRIES,
    backoff: float = DEFAULT_BACKOFF_S,
) -> requests.Response:
    """POST ``application/x-www-form-urlencoded`` fields and return the response."""
    last: Exception | None = None
    for attempt in range(retries + 1):
        with _session(headers) as s:
            try:
                resp = s.post(url, data=fields, timeout=timeout)
                resp.raise_for_status()
                return resp
            except requests.RequestException as exc:
                last = exc
                if attempt < retries:
                    time.sleep(backoff * (2**attempt))
    raise HttpFetchError(f"POST {url} failed after {retries + 1} attempts: {last}") from last


def get_bytes(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT_S,
    retries: int = DEFAULT_RETRIES,
    backoff: float = DEFAULT_BACKOFF_S,
) -> bytes:
    """GET the raw response body of ``url``."""
    last: Exception | None = None
    for attempt in range(retries + 1):
        with _session(headers) as s:
            try:
                resp = s.get(url, timeout=timeout)
                resp.raise_for_status()
                return resp.content
            except requests.RequestException as exc:
                last = exc
                if attempt < retries:
                    time.sleep(backoff * (2**attempt))
    raise HttpFetchError(f"GET {url} failed after {retries + 1} attempts: {last}") from last
