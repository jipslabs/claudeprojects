"""HackerNews Firebase API ingester — fetches top security stories."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from secnews.core.models import NewsItem
from secnews.sources import _safe_url, http_get

logger = logging.getLogger(__name__)

_TIMEOUT = 8
_HEADERS = {"User-Agent": "secnews/1.0 (security-digest-tool)"}
_SECURITY_KEYWORDS = {
    "security", "vulnerability", "exploit", "hack", "breach", "malware",
    "ransomware", "CVE", "zero-day", "phishing", "CISA", "threat", "attack",
    "injection", "XSS", "RCE", "authentication", "cryptography", "encryption",
    "privacy", "surveillance", "APT", "backdoor", "trojan", "worm",
}
_TOP_STORIES = 200   # how many top stories to scan
_MAX_ITEMS = 30      # max security items to return


def _fetch_item(base_url: str, item_id: int) -> dict | None:
    try:
        resp = http_get(
            f"{base_url}/item/{item_id}.json",
            timeout=_TIMEOUT,
            headers=_HEADERS,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return None


def _is_security_related(title: str) -> bool:
    title_lower = title.lower()
    return any(kw.lower() in title_lower for kw in _SECURITY_KEYWORDS)


def fetch(
    url: str,
    name: str,
    category: str,
    tier: int,
    cutoff: datetime,
) -> list[NewsItem]:
    # Fetch top story IDs
    try:
        resp = http_get(
            f"{url}/topstories.json",
            timeout=_TIMEOUT,
            headers=_HEADERS,
        )
        resp.raise_for_status()
        story_ids: list[int] = resp.json()[:_TOP_STORIES]
    except Exception as exc:
        logger.warning("HN top stories fetch failed: %s", exc)
        return []

    items: list[NewsItem] = []

    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(_fetch_item, url, sid): sid for sid in story_ids}
        for future in as_completed(futures, timeout=30):
            data = future.result()
            if not data or data.get("type") != "story":
                continue
            title = data.get("title", "").strip()
            if not title or not _is_security_related(title):
                continue

            ts = data.get("time", 0)
            published = datetime.fromtimestamp(ts, tz=timezone.utc)
            if published < cutoff:
                continue

            raw_link = data.get("url") or ""
            link = _safe_url(raw_link) or f"https://news.ycombinator.com/item?id={data['id']}"
            points = data.get("score", 0)

            items.append(
                NewsItem(
                    title=title,
                    url=link,
                    source_name=name,
                    source_category=category,
                    source_tier=tier,
                    published=published,
                    description=f"HackerNews | {points} points | {data.get('descendants', 0)} comments",
                    hn_points=points,
                )
            )

            if len(items) >= _MAX_ITEMS:
                break

    return items
