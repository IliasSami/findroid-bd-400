"""Google Play listing evidence fetcher.

Fetching a Play store page is legal, low-volume, and works from any network —
the store front is not bot-walled like the APK mirrors. We read the page's
``application/ld+json`` structured data (author, category, rating, price) plus
a couple of meta tags, and return a plain dict of *observed* listing evidence.

This never downloads APKs; its job is the benign verification round-trip
(``play_verification_date`` + author/sub-sector confirmation from the catalogue)
and public provenance for the release report.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, date, datetime

import requests

from .base import SourceError

PLAY_DETAIL_URL = "https://play.google.com/store/apps/details"
_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)

_LDJSON_RE = re.compile(r'<script[^>]*type="application/ld\+json"[^>]*>(.*?)</script>', re.S)


class PlayError(SourceError):
    """Raised when a Play listing cannot be retrieved or parsed."""


def _meta_items(html: str, itemprop: str) -> list[str]:
    out: list[str] = []
    for m in re.finditer(
        rf'<meta[^>]+itemprop="{itemprop}"[^>]*>', html, flags=re.I
    ):
        content = re.search(r'content="([^"]*)"', m.group(0))
        if content:
            out.append(content.group(1))
    return out


def fetch_play_listing(package_id: str, *, timeout: float = 30) -> dict:
    """Return observed listing evidence for ``package_id``.

    Raises :class:`PlayError` for anything that prevents an honest parse
    (404/redirected listing, no structured data). ``None`` fields mean the page
    simply did not expose that datum.
    """
    url = f"{PLAY_DETAIL_URL}?id={package_id}&hl=en&gl=bd"
    try:
        resp = requests.get(url, headers={"User-Agent": _UA}, timeout=timeout)
        resp.raise_for_status()
        html = resp.text
    except requests.RequestException as exc:
        raise PlayError(f"Play listing fetch failed for {package_id}: {exc}") from exc

    if "We're sorry" in html or "not available" in html[:5000]:
        raise PlayError(f"Play listing unavailable for {package_id}")

    ld = _first_software_application(html)
    if ld is None:
        raise PlayError(f"no SoftwareApplication structured data for {package_id}")

    author = ld.get("author") or {}
    if isinstance(author, list):
        author = author[0] if author else {}
    offers = ld.get("offers") or {}
    if isinstance(offers, list):
        offers = offers[0] if offers else {}
    rating = ld.get("aggregateRating") or {}
    if isinstance(rating, list):
        rating = rating[0] if rating else {}

    user_interaction = ld.get("userInteractionStatistic")
    return {
        "package_id": package_id,
        "url": url,
        "name": ld.get("name"),
        "author": author.get("name") if isinstance(author, dict) else None,
        "author_url": author.get("url") if isinstance(author, dict) else None,
        "category": ld.get("category"),
        "genre": ld.get("genre"),
        "price": _to_float(offers.get("price")),
        "price_currency": offers.get("priceCurrency"),
        "rating_value": _to_float(rating.get("ratingValue")),
        "rating_count": _to_int(rating.get("ratingCount")),
        "user_interaction_count": _interaction_count(user_interaction),
        "install_min": _install_min_from_text(_meta_items(html, "install")),
        "date_published": ld.get("datePublished"),
        "date_modified": ld.get("dateModified"),
        "software_version": _meta_items(html, "softwareVersion")[:1] or [None],
        "price_meta": _meta_items(html, "price")[:1] or [None],
        "fetched_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "fetch_date": date.today().isoformat(),
    }


def _first_software_application(html: str) -> dict | None:
    for block in _LDJSON_RE.findall(html):
        blob = block.strip()
        if not blob.startswith(("{", "[")):
            continue
        try:
            data = json.loads(blob)
        except ValueError:
            continue
        if isinstance(data, dict) and data.get("@type") == "SoftwareApplication":
            return data
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and item.get("@type") == "SoftwareApplication":
                    return item
    return None


def _to_float(value) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _to_int(value) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _interaction_count(value) -> int | None:
    if isinstance(value, dict):
        return _to_int(value.get("userInteractionCount"))
    if isinstance(value, list) and value and isinstance(value[0], dict):
        return _to_int(value[0].get("userInteractionCount"))
    return None


def _install_min_from_text(values: list[str]) -> str | None:
    # Play renders a bounded install range like "1,000,000+".
    for v in values:
        cleaned = v.strip()
        if cleaned:
            return cleaned
    return None


__all__ = ["PlayError", "fetch_play_listing"]
