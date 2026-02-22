"""RSS feed ingester."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Optional

import feedparser
import requests

from secnews.core.models import NewsItem

logger = logging.getLogger(__name__)

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_TIMEOUT = 10
_HEADERS = {"User-Agent": "secnews/1.0 (security-digest-tool)"}


def _parse_date(entry: dict) -> datetime:
    """Extract a timezone-aware datetime from a feedparser entry."""
    for attr in ("published", "updated", "created"):
        val = entry.get(f"{attr}_parsed")
        if val:
            import time as _time
            ts = _time.mktime(val)
            return datetime.fromtimestamp(ts, tz=timezone.utc)
    # Fallback: try raw string
    for attr in ("published", "updated"):
        raw = entry.get(attr, "")
        if raw:
            try:
                return parsedate_to_datetime(raw).astimezone(timezone.utc)
            except Exception:
                pass
    return datetime.now(timezone.utc)


def _extract_cves(text: str) -> list[str]:
    return list({m.upper() for m in _CVE_RE.findall(text)})


def fetch(
    url: str,
    name: str,
    category: str,
    tier: int,
    cutoff: datetime,
) -> list[NewsItem]:
    try:
        resp = requests.get(url, timeout=_TIMEOUT, headers=_HEADERS)
        resp.raise_for_status()
        feed = feedparser.parse(resp.content)
    except Exception as exc:
        logger.warning("RSS fetch failed for %s: %s", name, exc)
        return []

    items: list[NewsItem] = []
    for entry in feed.entries:
        title = entry.get("title", "").strip()
        link = entry.get("link", "").strip()
        if not title or not link:
            continue

        published = _parse_date(entry)
        if cutoff.tzinfo and published.tzinfo is None:
            published = published.replace(tzinfo=timezone.utc)
        if published < cutoff:
            continue

        summary = entry.get("summary", entry.get("description", ""))
        # Strip HTML tags from description
        summary = re.sub(r"<[^>]+>", " ", summary).strip()
        summary = re.sub(r"\s+", " ", summary)[:500]

        combined = f"{title} {summary}"
        cves = _extract_cves(combined)

        items.append(
            NewsItem(
                title=title,
                url=link,
                source_name=name,
                source_category=category,
                source_tier=tier,
                published=published,
                description=summary,
                cve_ids=cves,
            )
        )

    return items
