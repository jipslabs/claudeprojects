"""Tests for topic clustering."""

from datetime import datetime, timezone

import pytest

from secnews.core.cluster import cluster_items
from secnews.core.models import NewsItem


def _item(title: str, desc: str = "", score: float = 50.0) -> NewsItem:
    item = NewsItem(
        title=title,
        url=f"https://example.com/{hash(title)}",
        source_name="TestSource",
        source_category="blogs",
        source_tier=2,
        published=datetime.now(timezone.utc),
        description=desc,
        score=score,
    )
    return item


def test_items_sharing_keywords_are_clustered():
    items = [
        _item("Apache Log4j RCE vulnerability CVE-2021-44228", score=80),
        _item("Log4j exploit kit now targeting Apache servers", score=70),
        _item("Completely unrelated story about cookies", score=30),
    ]
    clusters = cluster_items(items)
    # The two log4j stories should be in the same cluster
    log4j_cluster = next(
        (c for c in clusters if any("log4j" in i.title.lower() for i in c.items) and c.name != "Other"),
        None,
    )
    assert log4j_cluster is not None
    assert len(log4j_cluster.items) == 2


def test_singleton_goes_to_other():
    items = [_item("A completely isolated story about nothing security related")]
    clusters = cluster_items(items)
    # Should end up in "Other" cluster
    other = next((c for c in clusters if c.name == "Other"), None)
    assert other is not None


def test_clusters_sorted_by_top_score():
    items = [
        _item("Ransomware group hits hospital systems", score=90),
        _item("Ransomware attack causes outages at city", score=85),
        _item("Minor XSS bug in web app", score=20),
        _item("XSS vulnerability found in popular site", score=25),
    ]
    clusters = cluster_items(items)
    scores = [c.top_score for c in clusters]
    assert scores == sorted(scores, reverse=True)


def test_lead_item_is_highest_scored():
    items = [
        _item("Cisco auth bypass CVE-2024-9999", score=75),
        _item("Cisco routers vulnerable to auth bypass", score=60),
        _item("Authentication bypass in Cisco gear", score=45),
    ]
    clusters = cluster_items(items)
    for c in clusters:
        if c.name != "Other":
            assert c.lead.score == max(i.score for i in c.items)
