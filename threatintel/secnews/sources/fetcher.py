"""Parallel source fetcher — coordinates all ingesters."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

import yaml

from secnews.core.models import NewsItem
from secnews.sources import rss, nvd, osv, hn, cisa, json_feed

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


_REQUIRED_CONFIG_KEYS = {"sources"}


def _validate_config(cfg: Any, path: str) -> None:
    """Raise ValueError with a clear message if config is missing required structure."""
    if not isinstance(cfg, dict):
        raise ValueError(f"Config at '{path}' must be a YAML mapping, got {type(cfg).__name__}")
    missing = _REQUIRED_CONFIG_KEYS - cfg.keys()
    if missing:
        raise ValueError(f"Config at '{path}' is missing required keys: {missing}")
    sources = cfg.get("sources", {})
    if not isinstance(sources, dict) or not sources:
        raise ValueError(f"Config at '{path}': 'sources' must be a non-empty mapping")


def load_config(config_path: str) -> dict[str, Any]:
    with open(config_path) as f:
        cfg = yaml.safe_load(f)
    _validate_config(cfg, config_path)
    return cfg


def _fetch_source(source: dict[str, Any], category: str, cutoff: datetime) -> list[NewsItem]:
    """Dispatch to the correct ingester based on source type."""
    if not source.get("enabled", True):
        return []

    src_type = source["type"]
    name = source["name"]
    url = source["url"]
    tier = source.get("tier", 3)

    try:
        match src_type:
            case "rss":
                items = rss.fetch(url, name, category, tier, cutoff)
            case "nvd_api":
                items = nvd.fetch(url, name, category, tier, cutoff)
            case "osv_api":
                items = osv.fetch(url, name, category, tier, cutoff)
            case "hn_api":
                items = hn.fetch(url, name, category, tier, cutoff)
            case "json_api":
                items = cisa.fetch(url, name, category, tier, cutoff) if "cisa" in url.lower() else json_feed.fetch(url, name, category, tier, cutoff)
            case _:
                logger.warning("Unknown source type %s for %s", src_type, name)
                items = []
        logger.debug("Fetched %d items from %s", len(items), name)
        return items
    except Exception as exc:
        logger.warning("Failed to fetch %s (%s): %s", name, url, exc)
        return []


def fetch_all(
    config: dict[str, Any],
    hours: int,
    source_filter: list[str] | None,
    max_workers: int = 20,
) -> list[NewsItem]:
    """Fetch all enabled sources in parallel, returning items within the look-back window."""
    cutoff_dt = _utcnow()
    from datetime import timedelta
    cutoff = cutoff_dt - timedelta(hours=hours)

    tasks: list[tuple[dict, str]] = []
    categories = config.get("sources", {})

    for category, sources in categories.items():
        if source_filter and category not in source_filter:
            continue
        for source in sources:
            tasks.append((source, category))

    all_items: list[NewsItem] = []
    timeout = config.get("fetch", {}).get("timeout_seconds", 10)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_fetch_source, src, cat, cutoff): (src["name"], cat)
            for src, cat in tasks
        }
        for future in as_completed(futures, timeout=60):
            src_name, cat = futures[future]
            try:
                items = future.result(timeout=timeout + 5)
                all_items.extend(items)
            except Exception as exc:
                logger.warning("Source %s timed out or errored: %s", src_name, exc)

    return all_items
