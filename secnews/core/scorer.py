"""Scoring & ranking: 0–100 heuristic score per NewsItem."""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

from secnews.core.models import NewsItem


def _cvss_component(cvss: float | None, weight: float) -> float:
    """Map CVSS 0–10 → 0–weight."""
    if cvss is None:
        return 0.0
    return (min(cvss, 10.0) / 10.0) * weight


def _recency_component(item: NewsItem, now: datetime, weight: float) -> float:
    """
    Decay function: full score at 0h, halves every 12h.
    score = weight * 0.5^(age_hours / 12)
    """
    age = item.age_hours(now)
    return weight * math.pow(0.5, age / 12.0)


def _tier_component(tier: int, weight: float) -> float:
    """Tier 1 = full weight, tier 2 = 66%, tier 3 = 33%."""
    tier_scores = {1: 1.0, 2: 0.66, 3: 0.33}
    return tier_scores.get(tier, 0.1) * weight


def _engagement_component(hn_points: int, weight: float) -> float:
    """Log-scale HN engagement. 500+ points → full weight."""
    if hn_points <= 0:
        return 0.0
    return min(math.log(hn_points + 1) / math.log(501), 1.0) * weight


def _watchlist_component(item: NewsItem, watchlist: list[str], weight: float) -> float:
    """Each watchlist keyword hit in title/desc adds partial score."""
    if not watchlist:
        return 0.0
    combined = f"{item.title} {item.description}".lower()
    hits = sum(1 for kw in watchlist if kw.lower() in combined)
    # Cap at 3 hits for full score
    ratio = min(hits / 3, 1.0)
    return ratio * weight


def score_item(
    item: NewsItem,
    watchlist: list[str],
    weights: dict[str, float],
    now: datetime,
) -> float:
    cvss_w = weights.get("cvss_weight", 30)
    recency_w = weights.get("recency_weight", 25)
    tier_w = weights.get("source_tier_weight", 20)
    engage_w = weights.get("engagement_weight", 10)
    watchlist_w = weights.get("watchlist_weight", 15)

    score = (
        _cvss_component(item.cvss_score, cvss_w)
        + _recency_component(item, now, recency_w)
        + _tier_component(item.source_tier, tier_w)
        + _engagement_component(item.hn_points, engage_w)
        + _watchlist_component(item, watchlist, watchlist_w)
    )
    return round(min(score, 100.0), 1)


def score_all(
    items: list[NewsItem],
    config: dict[str, Any],
) -> list[NewsItem]:
    """Compute and assign scores to all items, return sorted descending."""
    watchlist = config.get("watchlist", [])
    weights = config.get("scoring", {})
    now = datetime.now(timezone.utc)

    for item in items:
        item.score = score_item(item, watchlist, weights, now)

    return sorted(items, key=lambda i: -i.score)
