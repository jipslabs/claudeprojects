"""Deduplication: fingerprint-based exact dedup + fuzzy title matching."""

from __future__ import annotations

import logging
from typing import Any

from rapidfuzz import fuzz

from secnews.core.models import NewsItem

logger = logging.getLogger(__name__)

# Source priority: lower tier number = higher priority
_TIER_PRIORITY = {1: 0, 2: 1, 3: 2}


def _normalize_title(title: str) -> str:
    import re
    return re.sub(r"\W+", " ", title.lower()).strip()


def deduplicate(
    items: list[NewsItem],
    similarity_threshold: int = 85,
) -> list[NewsItem]:
    """
    1. Exact dedup by content fingerprint.
    2. Fuzzy near-duplicate detection on normalized titles.
    When duplicates are found, keep the highest-priority source item
    and append other source names as attribution.
    """
    # --- Pass 1: exact fingerprint dedup ---
    seen_fps: dict[str, NewsItem] = {}
    after_exact: list[NewsItem] = []

    for item in items:
        fp = item.fingerprint
        if fp in seen_fps:
            canonical = seen_fps[fp]
            if item.source_tier < canonical.source_tier:
                # Swap to higher-priority source, carry attribution
                item.duplicate_sources = canonical.duplicate_sources + [canonical.source_name]
                seen_fps[fp] = item
            else:
                canonical.duplicate_sources.append(item.source_name)
        else:
            seen_fps[fp] = item

    after_exact = list(seen_fps.values())
    logger.debug("After exact dedup: %d items (was %d)", len(after_exact), len(items))

    # --- Pass 2: fuzzy title dedup ---
    # Sort by tier then recency so we keep the best item as canonical
    after_exact.sort(key=lambda i: (i.source_tier, -i.published.timestamp()))

    canonical_list: list[NewsItem] = []
    canonical_titles: list[str] = []

    for item in after_exact:
        norm = _normalize_title(item.title)
        is_dup = False
        for idx, canon_norm in enumerate(canonical_titles):
            ratio = fuzz.ratio(norm, canon_norm)
            if ratio >= similarity_threshold:
                # Merge attribution into the canonical item
                canonical_list[idx].duplicate_sources.append(item.source_name)
                is_dup = True
                break
        if not is_dup:
            canonical_list.append(item)
            canonical_titles.append(norm)

    logger.debug(
        "After fuzzy dedup: %d items (removed %d)",
        len(canonical_list),
        len(after_exact) - len(canonical_list),
    )
    return canonical_list
