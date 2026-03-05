"""Topic clustering: group items that share 2+ significant keywords."""

from __future__ import annotations

import logging
from collections import defaultdict

from secnews.core.keywords import extract_keywords
from secnews.core.models import Cluster, NewsItem

logger = logging.getLogger(__name__)

_MIN_SHARED_KEYWORDS = 2
_SINGLETON_CLUSTER_NAME = "Other"


def _enrich_keywords(item: NewsItem) -> None:
    """Populate item.keywords if not already set."""
    if not item.keywords:
        combined = f"{item.title} {item.description} {' '.join(item.cve_ids)}"
        item.keywords = extract_keywords(combined)


def cluster_items(items: list[NewsItem]) -> list[Cluster]:
    """
    Group items into clusters based on shared keywords.
    Items with no cluster partners are placed in a catch-all 'Other' cluster.
    Returns clusters sorted by top score (descending).
    """
    for item in items:
        _enrich_keywords(item)

    n = len(items)
    # Union-Find for grouping
    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: int, y: int) -> None:
        px, py = find(x), find(y)
        if px != py:
            parent[px] = py

    # Build index: keyword -> list of item indices
    kw_index: dict[str, list[int]] = defaultdict(list)
    for idx, item in enumerate(items):
        for kw in item.keywords:
            kw_index[kw].append(idx)

    # Union items that share keywords
    shared_counts: dict[tuple[int, int], set[str]] = defaultdict(set)
    for kw, indices in kw_index.items():
        for i in range(len(indices)):
            for j in range(i + 1, len(indices)):
                a, b = indices[i], indices[j]
                pair = (min(a, b), max(a, b))
                shared_counts[pair].add(kw)

    for (a, b), shared in shared_counts.items():
        if len(shared) >= _MIN_SHARED_KEYWORDS:
            union(a, b)

    # Group by root
    groups: dict[int, list[int]] = defaultdict(list)
    for idx in range(n):
        groups[find(idx)].append(idx)

    clusters: list[Cluster] = []
    singletons: list[NewsItem] = []

    for root, indices in groups.items():
        group_items = [items[i] for i in indices]

        if len(group_items) == 1:
            singletons.append(group_items[0])
            continue

        # Name the cluster from the most common significant keyword
        kw_freq: dict[str, int] = defaultdict(int)
        for item in group_items:
            for kw in item.keywords:
                kw_freq[kw] += 1

        # Pick the most representative keyword (prefer CVEs, then attack types)
        sorted_kws = sorted(kw_freq.items(), key=lambda x: -x[1])
        name_kw = sorted_kws[0][0] if sorted_kws else "Unknown"

        # Find shared keywords (appear in 2+ items)
        shared_kws = [kw for kw, cnt in kw_freq.items() if cnt >= 2]

        cluster = Cluster(
            name=name_kw.upper() if name_kw.startswith("CVE-") else name_kw.title(),
            items=sorted(group_items, key=lambda i: -i.score),
            shared_keywords=shared_kws[:5],
        )
        clusters.append(cluster)

    # Singletons go into the catch-all cluster
    if singletons:
        clusters.append(
            Cluster(
                name=_SINGLETON_CLUSTER_NAME,
                items=sorted(singletons, key=lambda i: -i.score),
                shared_keywords=[],
            )
        )

    # Sort clusters by their top-scoring item
    clusters.sort(key=lambda c: -c.top_score)
    logger.debug(
        "Clustered %d items into %d clusters (%d singletons in 'Other')",
        n,
        len(clusters),
        len(singletons),
    )
    return clusters
