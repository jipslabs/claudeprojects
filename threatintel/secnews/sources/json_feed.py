"""Generic JSON feed ingester for sources not covered by dedicated modules."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

from secnews.core.models import NewsItem
from secnews.sources import _safe_url, http_get

logger = logging.getLogger(__name__)

_TIMEOUT = 10
_HEADERS = {"User-Agent": "secnews/1.0 (security-digest-tool)"}
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def fetch(
    url: str,
    name: str,
    category: str,
    tier: int,
    cutoff: datetime,
) -> list[NewsItem]:
    try:
        resp = http_get(url, timeout=_TIMEOUT, headers=_HEADERS)
        resp.raise_for_status()
        ct = resp.headers.get("Content-Type", "")
        if "json" not in ct:
            logger.warning("JSON feed %s: unexpected Content-Type '%s'", name, ct)
        data = resp.json()
    except Exception as exc:
        logger.warning("JSON feed fetch failed for %s: %s", name, exc)
        return []

    # Handle both list-of-items and {items: [...]} structures
    if isinstance(data, list):
        raw_items = data
    elif isinstance(data, dict):
        for key in ("items", "data", "entries", "results", "vulnerabilities"):
            if key in data:
                raw_items = data[key]
                break
        else:
            raw_items = []
    else:
        return []

    items: list[NewsItem] = []
    for raw in raw_items[:50]:
        title = (
            raw.get("title") or raw.get("name") or raw.get("summary") or ""
        ).strip()
        link = _safe_url(
            (raw.get("url") or raw.get("link") or raw.get("html_url") or "").strip()
        )
        if not title or not link:
            continue

        desc = re.sub(r"<[^>]+>", " ", raw.get("description", raw.get("body", ""))).strip()[:500]

        # Try various date fields
        date_str = raw.get("published_at") or raw.get("updated_at") or raw.get("created_at") or ""
        try:
            published = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except Exception:
            published = datetime.now(timezone.utc)

        if published < cutoff:
            continue

        cves = list({m.upper() for m in _CVE_RE.findall(f"{title} {desc}")})

        items.append(
            NewsItem(
                title=title,
                url=link,
                source_name=name,
                source_category=category,
                source_tier=tier,
                published=published,
                description=desc,
                cve_ids=cves,
            )
        )

    return items
