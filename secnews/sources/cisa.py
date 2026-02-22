"""CISA Known Exploited Vulnerabilities (KEV) catalog ingester."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import requests

from secnews.core.models import NewsItem

logger = logging.getLogger(__name__)

_TIMEOUT = 15
_HEADERS = {"User-Agent": "secnews/1.0 (security-digest-tool)"}


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
        data = resp.json()
    except Exception as exc:
        logger.warning("CISA KEV fetch failed: %s", exc)
        return []

    items: list[NewsItem] = []
    for vuln in data.get("vulnerabilities", []):
        date_added_str = vuln.get("dateAdded", "")
        try:
            date_added = datetime.strptime(date_added_str, "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
        except Exception:
            date_added = datetime.now(timezone.utc)

        if date_added < cutoff:
            continue

        cve_id = vuln.get("cveID", "")
        product = vuln.get("product", "")
        vendor = vuln.get("vendorProject", "")
        vuln_name = vuln.get("vulnerabilityName", "")
        description = vuln.get("shortDescription", "")[:500]
        due_date = vuln.get("dueDate", "")

        title = f"[CISA KEV] {cve_id} — {vendor} {product}: {vuln_name}"
        if due_date:
            description = f"Required patch by {due_date}. {description}"

        link = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

        items.append(
            NewsItem(
                title=title,
                url=link,
                source_name=name,
                source_category=category,
                source_tier=tier,
                published=date_added,
                description=description,
                cve_ids=[cve_id] if cve_id else [],
                # CISA KEV entries are all actively exploited — boost score
                cvss_score=9.0,  # treated as critical floor
            )
        )

    return items
