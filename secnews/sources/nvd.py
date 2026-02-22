"""NVD CVE API v2 ingester."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import requests

from secnews.core.models import NewsItem

logger = logging.getLogger(__name__)

_TIMEOUT = 15
_HEADERS = {"User-Agent": "secnews/1.0 (security-digest-tool)"}
_MAX_RESULTS = 50


def fetch(
    url: str,
    name: str,
    category: str,
    tier: int,
    cutoff: datetime,
) -> list[NewsItem]:
    now = datetime.now(timezone.utc)
    pub_start = cutoff.strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end = now.strftime("%Y-%m-%dT%H:%M:%S.000")

    params = {
        "pubStartDate": pub_start,
        "pubEndDate": pub_end,
        "resultsPerPage": _MAX_RESULTS,
    }

    try:
        resp = requests.get(url, params=params, timeout=_TIMEOUT, headers=_HEADERS)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        logger.warning("NVD fetch failed: %s", exc)
        return []

    items: list[NewsItem] = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        descriptions = cve.get("descriptions", [])
        desc = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "",
        )[:500]

        # Title = CVE ID + first 80 chars of description
        short_desc = desc[:80] + ("..." if len(desc) > 80 else "")
        title = f"{cve_id}: {short_desc}" if short_desc else cve_id

        # CVSS score
        cvss_score: float | None = None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(key, [])
            if metric_list:
                cvss_score = float(
                    metric_list[0].get("cvssData", {}).get("baseScore", 0) or 0
                )
                break

        # Published date
        pub_str = cve.get("published", "")
        try:
            published = datetime.fromisoformat(pub_str.replace("Z", "+00:00"))
        except Exception:
            published = datetime.now(timezone.utc)

        link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        items.append(
            NewsItem(
                title=title,
                url=link,
                source_name=name,
                source_category=category,
                source_tier=tier,
                published=published,
                description=desc,
                cvss_score=cvss_score,
                cve_ids=[cve_id] if cve_id else [],
            )
        )

    return items
