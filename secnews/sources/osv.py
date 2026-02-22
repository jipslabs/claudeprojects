"""OSV.dev ingester — fetches recent vulnerabilities via the public GCS HTTP export."""

from __future__ import annotations

import io
import logging
import zipfile
from datetime import datetime, timezone

import requests

from secnews.core.models import NewsItem

logger = logging.getLogger(__name__)

_TIMEOUT = 20
_HEADERS = {"User-Agent": "secnews/1.0 (security-digest-tool)"}

# OSV public GCS export: each ecosystem has a zip of JSON files.
# We fetch a small, curated set of ecosystems via their all.zip.
# URL pattern: https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip
_ECOSYSTEMS = ["PyPI", "npm", "Go", "Maven", "RubyGems", "crates.io", "NuGet"]
_MAX_PER_ECOSYSTEM = 8   # cap to keep fetch time reasonable


def _parse_osv_record(record: dict, name: str, category: str, tier: int, cutoff: datetime) -> NewsItem | None:
    """Convert a raw OSV JSON record to a NewsItem, or None if outside window."""
    vuln_id = record.get("id", "")
    summary = record.get("summary", "")
    details = record.get("details", "")[:500]
    aliases = record.get("aliases", [])
    cves = [a for a in aliases if a.startswith("CVE-")]

    modified_str = record.get("modified", record.get("published", ""))
    try:
        modified = datetime.fromisoformat(modified_str.replace("Z", "+00:00"))
    except Exception:
        return None

    if modified < cutoff:
        return None

    title = f"{vuln_id}: {summary}" if summary else vuln_id
    link = f"https://osv.dev/vulnerability/{vuln_id}"

    # Extract CVSS base score from vector string if present
    cvss_score: float | None = None
    for sev in record.get("severity", []):
        if sev.get("type") in ("CVSS_V3", "CVSS_V4"):
            vector = sev.get("score", "")
            # Vectors look like "CVSS:3.1/AV:N/.../BS:9.8" — try to pull /BS: segment
            import re
            m = re.search(r"BS:([\d.]+)", vector)
            if m:
                try:
                    cvss_score = float(m.group(1))
                except ValueError:
                    pass
            break

    return NewsItem(
        title=title,
        url=link,
        source_name=name,
        source_category=category,
        source_tier=tier,
        published=modified,
        description=details,
        cvss_score=cvss_score,
        cve_ids=cves,
    )


def _fetch_ecosystem(ecosystem: str, name: str, category: str, tier: int, cutoff: datetime) -> list[NewsItem]:
    """Download the ecosystem zip and parse the most recently modified records."""
    zip_url = f"https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
    try:
        resp = requests.get(zip_url, timeout=_TIMEOUT, headers=_HEADERS, stream=True)
        resp.raise_for_status()
        content = resp.content
    except Exception as exc:
        logger.warning("OSV zip fetch failed for %s: %s", ecosystem, exc)
        return []

    items: list[NewsItem] = []
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            import json
            # Sort entries by file name (OSV IDs are roughly chronological)
            names = sorted(zf.namelist(), reverse=True)
            for fname in names:
                if not fname.endswith(".json"):
                    continue
                try:
                    with zf.open(fname) as f:
                        record = json.load(f)
                except Exception:
                    continue

                item = _parse_osv_record(record, name, category, tier, cutoff)
                if item:
                    items.append(item)
                    if len(items) >= _MAX_PER_ECOSYSTEM:
                        break
    except zipfile.BadZipFile as exc:
        logger.warning("OSV bad zip for %s: %s", ecosystem, exc)

    return items


def fetch(
    url: str,
    name: str,
    category: str,
    tier: int,
    cutoff: datetime,
) -> list[NewsItem]:
    """Fetch recent OSV vulnerabilities across major ecosystems."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    all_items: list[NewsItem] = []
    with ThreadPoolExecutor(max_workers=len(_ECOSYSTEMS)) as executor:
        futures = {
            executor.submit(_fetch_ecosystem, eco, name, category, tier, cutoff): eco
            for eco in _ECOSYSTEMS
        }
        for future in as_completed(futures, timeout=30):
            eco = futures[future]
            try:
                items = future.result()
                logger.debug("OSV %s: %d items", eco, len(items))
                all_items.extend(items)
            except Exception as exc:
                logger.warning("OSV ecosystem %s failed: %s", eco, exc)

    return all_items
