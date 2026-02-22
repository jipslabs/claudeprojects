"""Tests for scoring logic."""

from datetime import datetime, timedelta, timezone

import pytest

from secnews.core.models import NewsItem
from secnews.core.scorer import score_item


_NOW = datetime.now(timezone.utc)
_WEIGHTS = {
    "cvss_weight": 30,
    "recency_weight": 25,
    "source_tier_weight": 20,
    "engagement_weight": 10,
    "watchlist_weight": 15,
}


def _item(
    cvss: float | None = None,
    age_hours: float = 1,
    tier: int = 2,
    hn_points: int = 0,
    title: str = "Test item",
) -> NewsItem:
    pub = _NOW - timedelta(hours=age_hours)
    return NewsItem(
        title=title,
        url="https://example.com",
        source_name="TestSource",
        source_category="blogs",
        source_tier=tier,
        published=pub,
        cvss_score=cvss,
        hn_points=hn_points,
    )


def test_critical_cvss_boosts_score():
    item = _item(cvss=9.8, age_hours=1, tier=1)
    score = score_item(item, watchlist=[], weights=_WEIGHTS, now=_NOW)
    assert score >= 60  # critical CVSS + tier 1 + fresh = high score


def test_old_item_lower_score():
    fresh = _item(cvss=7.0, age_hours=1)
    stale = _item(cvss=7.0, age_hours=72)
    fresh_score = score_item(fresh, [], _WEIGHTS, _NOW)
    stale_score = score_item(stale, [], _WEIGHTS, _NOW)
    assert fresh_score > stale_score


def test_tier1_beats_tier3():
    t1 = _item(tier=1, age_hours=2)
    t3 = _item(tier=3, age_hours=2)
    s1 = score_item(t1, [], _WEIGHTS, _NOW)
    s3 = score_item(t3, [], _WEIGHTS, _NOW)
    assert s1 > s3


def test_watchlist_boost():
    base = _item(title="Some generic news story", tier=2, age_hours=5)
    watched = _item(title="Critical ransomware zero-day RCE exploit", tier=2, age_hours=5)
    watchlist = ["ransomware", "zero-day", "RCE"]
    base_score = score_item(base, watchlist=[], weights=_WEIGHTS, now=_NOW)
    watched_score = score_item(watched, watchlist=watchlist, weights=_WEIGHTS, now=_NOW)
    assert watched_score > base_score


def test_score_capped_at_100():
    item = _item(cvss=10.0, age_hours=0, tier=1, hn_points=1000,
                 title="ransomware zero-day RCE active exploitation CISA KEV")
    score = score_item(item, watchlist=["ransomware", "zero-day", "RCE"], weights=_WEIGHTS, now=_NOW)
    assert score <= 100.0


def test_no_cvss_still_scores():
    item = _item(cvss=None, age_hours=2, tier=2)
    score = score_item(item, [], _WEIGHTS, _NOW)
    assert score > 0
