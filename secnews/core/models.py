"""Core data models for secnews."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from secnews.core.incident import IncidentDetail


@dataclass
class NewsItem:
    """A single security news item from any source."""

    title: str
    url: str
    source_name: str
    source_category: str  # cve | blogs | community | advisories | threat_intel
    source_tier: int       # 1 = highest priority
    published: datetime
    description: str = ""
    cvss_score: Optional[float] = None
    cve_ids: list[str] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)
    hn_points: int = 0
    score: float = 0.0
    duplicate_sources: list[str] = field(default_factory=list)
    incident: Optional["IncidentDetail"] = field(default=None, repr=False)

    @property
    def fingerprint(self) -> str:
        """Stable content fingerprint based on normalized title + URL."""
        norm_title = re.sub(r"\W+", " ", self.title.lower()).strip()
        norm_url = self.url.split("?")[0].rstrip("/").lower()
        raw = f"{norm_title}|{norm_url}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def age_hours(self, now: datetime) -> float:
        pub = self.published
        if pub.tzinfo is not None:
            from datetime import timezone
            now = now.replace(tzinfo=timezone.utc) if now.tzinfo is None else now
        else:
            now = now.replace(tzinfo=None)
        delta = now - pub
        return max(delta.total_seconds() / 3600, 0)


@dataclass
class Cluster:
    """A group of related NewsItems sharing significant keywords."""

    name: str
    items: list[NewsItem] = field(default_factory=list)
    shared_keywords: list[str] = field(default_factory=list)

    @property
    def top_score(self) -> float:
        return max((i.score for i in self.items), default=0.0)

    @property
    def lead(self) -> NewsItem:
        return max(self.items, key=lambda i: i.score)
