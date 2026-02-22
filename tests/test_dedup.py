"""Tests for deduplication logic."""

from datetime import datetime, timezone

import pytest

from secnews.core.dedup import deduplicate
from secnews.core.models import NewsItem


def _item(title: str, url: str, tier: int = 2) -> NewsItem:
    return NewsItem(
        title=title,
        url=url,
        source_name=f"Source-{tier}",
        source_category="blogs",
        source_tier=tier,
        published=datetime.now(timezone.utc),
    )


def test_exact_fingerprint_dedup():
    items = [
        _item("Critical RCE in Apache", "https://example.com/rce", tier=2),
        _item("Critical RCE in Apache", "https://example.com/rce", tier=1),
    ]
    result = deduplicate(items, similarity_threshold=85)
    assert len(result) == 1
    # Higher priority (lower tier number) should win
    assert result[0].source_tier == 1


def test_fuzzy_dedup():
    items = [
        _item("Critical vulnerability found in Apache HTTP Server", "https://a.com/1"),
        _item("Critical vulnerability found in Apache HTTP Server!", "https://b.com/2"),
    ]
    result = deduplicate(items, similarity_threshold=85)
    assert len(result) == 1


def test_distinct_items_preserved():
    items = [
        _item("Apache RCE vulnerability CVE-2024-1234", "https://a.com/1"),
        _item("Cisco IOS authentication bypass", "https://b.com/2"),
        _item("Ransomware group targets hospitals", "https://c.com/3"),
    ]
    result = deduplicate(items)
    assert len(result) == 3


def test_duplicate_attribution():
    items = [
        _item("Log4Shell exploit in the wild", "https://source1.com/log4shell", tier=1),
        _item("Log4Shell exploit in the wild", "https://source2.com/log4shell", tier=2),
    ]
    result = deduplicate(items)
    assert len(result) == 1
    assert "Source-2" in result[0].duplicate_sources or "Source-1" in result[0].duplicate_sources
