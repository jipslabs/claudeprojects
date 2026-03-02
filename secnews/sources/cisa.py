"""CISA Known Exploited Vulnerabilities (KEV) catalog ingester."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

import requests

from secnews.core.models import NewsItem

logger = logging.getLogger(__name__)

_TIMEOUT = 15
_HEADERS = {"User-Agent": "secnews/1.0 (security-digest-tool)"}

# CVE year filter — older CVEs still appear in KEV when CISA adds them.
# We only surface ones from 2018+ by default to keep the feed relevant.
# The full catalog is still fetched; this filters the displayed results.
_MIN_CVE_YEAR = 2018
_CVE_YEAR_RE = re.compile(r"CVE-(\d{4})-")


def _cve_year(cve_id: str) -> int | None:
    m = _CVE_YEAR_RE.match(cve_id)
    return int(m.group(1)) if m else None


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
        ct = resp.headers.get("Content-Type", "")
        if "json" not in ct:
            logger.warning("CISA KEV: unexpected Content-Type '%s'", ct)
        data = resp.json()
    except Exception as exc:
        logger.warning("CISA KEV fetch failed: %s", exc)
        return []

    items: list[NewsItem] = []
    for vuln in data.get("vulnerabilities", []):
        # Filter by dateAdded (when CISA added it to KEV, i.e. within look-back window)
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

        # Skip very old CVEs — they clutter incident reports
        # (They appear because CISA retroactively adds exploited legacy vulns)
        year = _cve_year(cve_id)
        if year is not None and year < _MIN_CVE_YEAR:
            logger.debug("Skipping legacy CVE %s (year %d < %d)", cve_id, year, _MIN_CVE_YEAR)
            continue

        title = f"[CISA KEV] {cve_id} — {vendor} {product}: {vuln_name}"

        # All KEV entries are actively exploited AND have a mandatory patch deadline
        # → is_fixed = True (patch exists, that's why CISA mandates it)
        # We make this explicit in the description so heuristic extraction agrees
        if due_date:
            description = (
                f"Patch required by {due_date}. Actively exploited in the wild. "
                f"Patch is available. {description}"
            )
        else:
            description = f"Actively exploited in the wild. Patch is available. {description}"

        items.append(
            NewsItem(
                title=title,
                url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                source_name=name,
                source_category=category,
                source_tier=tier,
                published=date_added,
                description=description,
                cve_ids=[cve_id] if cve_id else [],
                cvss_score=9.0,  # all KEV = critical floor
            )
        )

    return items
