"""OSV.dev API ingester — queries recent vulnerabilities."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import requests

from secnews.core.models import NewsItem

logger = logging.getLogger(__name__)

_TIMEOUT = 15
_HEADERS = {
    "User-Agent": "secnews/1.0 (security-digest-tool)",
    "Content-Type": "application/json",
}
_ECOSYSTEMS = ["PyPI", "npm", "Go", "Maven", "RubyGems", "crates.io", "NuGet"]


def fetch(
    url: str,
    name: str,
    category: str,
    tier: int,
    cutoff: datetime,
) -> list[NewsItem]:
    """Query OSV for recently modified vulns across major ecosystems."""
    # OSV query endpoint for listing recent vulns
    list_url = "https://api.osv.dev/v1/query"
    items: list[NewsItem] = []

    for ecosystem in _ECOSYSTEMS:
        payload = {
            "query": {
                "package": {"ecosystem": ecosystem},
            }
        }
        try:
            resp = requests.post(list_url, json=payload, timeout=_TIMEOUT, headers=_HEADERS)
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            logger.warning("OSV fetch failed for ecosystem %s: %s", ecosystem, exc)
            continue

        for vuln in data.get("vulns", [])[:20]:  # cap per ecosystem
            vuln_id = vuln.get("id", "")
            summary = vuln.get("summary", "")
            details = vuln.get("details", "")[:500]
            aliases = vuln.get("aliases", [])
            cves = [a for a in aliases if a.startswith("CVE-")]

            title = f"{vuln_id}: {summary}" if summary else vuln_id

            # Parse modified date
            modified_str = vuln.get("modified", vuln.get("published", ""))
            try:
                published = datetime.fromisoformat(modified_str.replace("Z", "+00:00"))
            except Exception:
                published = datetime.now(timezone.utc)

            if published < cutoff:
                continue

            link = f"https://osv.dev/vulnerability/{vuln_id}"

            # CVSS from severity block
            cvss_score: float | None = None
            for sev in vuln.get("severity", []):
                if sev.get("type") == "CVSS_V3":
                    score_str = sev.get("score", "")
                    # score_str is a CVSS vector; extract base score if numeric
                    try:
                        cvss_score = float(score_str)
                    except ValueError:
                        pass
                    break

            items.append(
                NewsItem(
                    title=title,
                    url=link,
                    source_name=name,
                    source_category=category,
                    source_tier=tier,
                    published=published,
                    description=details,
                    cvss_score=cvss_score,
                    cve_ids=cves,
                )
            )

    return items
