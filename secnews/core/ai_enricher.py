"""
AI enrichment via Anthropic Claude API.

Uses claude-haiku for fast, cheap structured extraction of:
  - Incident type classification
  - Victim (company/product)
  - Impact summary
  - Root cause
  - Fix status
  - Severity rationale
  - AI relevance score boost

Falls back gracefully to heuristic extraction if:
  - ANTHROPIC_API_KEY is not set
  - The API call fails or times out
  - The response is not valid JSON
"""

from __future__ import annotations

import json
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from secnews.core.incident import IncidentDetail

logger = logging.getLogger(__name__)

# ── Prompt ────────────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """You are a senior cybersecurity analyst. Your job is to extract
structured intelligence from security news headlines and descriptions.
Be precise, concise, and factual. Only report what is stated or strongly implied
in the text — do not speculate. Return valid JSON only, no prose."""

_USER_PROMPT = """Analyze this cybersecurity news item and extract structured fields.

TITLE: {title}
DESCRIPTION: {description}

Return a JSON object with exactly these fields:
{{
  "incident_type": one of "Ransomware" | "Data Breach" | "Supply Chain Attack" | "Phishing" | "Zero-Day Exploit" | "DDoS Attack" | "Nation-State / APT" | "Authentication Bypass" | "Remote Code Execution" | "Privilege Escalation" | "SQL Injection" | "Malware" | "Vulnerability" | "Security Breach" | "Service Disruption" | "Cryptojacking" | "Other",
  "victim": "the specific company, product, or service that was breached or is vulnerable — null if not mentioned",
  "impact": "what was stolen, disrupted, or damaged (include numbers if stated, e.g. '73 million records exposed') — null if not reported",
  "root_cause": "the specific CVE ID, attack vector, or technical mechanism (e.g. 'CVE-2024-1234', 'phishing via help desk impersonation', 'misconfigured S3 bucket') — null if under investigation",
  "is_fixed": true if a patch/fix/workaround is available, false if actively exploited with no fix, null if unknown,
  "severity_rationale": "one concise sentence explaining the real-world significance of this incident",
  "ai_score_boost": a number from 0 to 20 representing how much to boost the relevance score based on severity and impact (0=low, 20=critical active breach)
}}

Rules:
- victim must be a proper noun (company/product name), not a generic term like "users" or "systems"
- impact should quantify damage when possible
- root_cause should be specific, not generic like "cyberattack"
- Respond with JSON only. No markdown, no explanation."""


# ── Client management ─────────────────────────────────────────────────────────

_client = None


def _get_client():
    """Lazy-initialize the Anthropic client."""
    global _client
    if _client is None:
        try:
            import anthropic
            api_key = os.environ.get("ANTHROPIC_API_KEY")
            if not api_key:
                raise ValueError("ANTHROPIC_API_KEY environment variable not set")
            _client = anthropic.Anthropic(api_key=api_key)
        except ImportError:
            raise ImportError(
                "anthropic package not installed. Run: pip install anthropic"
            )
    return _client


def is_available() -> bool:
    """Check if AI enrichment is available (key set + package installed)."""
    try:
        import anthropic  # noqa: F401
        return bool(os.environ.get("ANTHROPIC_API_KEY"))
    except ImportError:
        return False


# ── Core extraction ───────────────────────────────────────────────────────────

def _parse_response(raw: str) -> dict[str, Any]:
    """Extract JSON from Claude's response, handling minor formatting issues."""
    # Strip markdown code fences if present
    raw = raw.strip()
    raw = re.sub(r"^```(?:json)?\s*", "", raw)
    raw = re.sub(r"\s*```$", "", raw)
    return json.loads(raw.strip())


def enrich_item(
    title: str,
    description: str,
    model: str = "claude-haiku-4-5",
    timeout: int = 15,
) -> dict[str, Any] | None:
    """
    Call Claude to extract structured incident intelligence.
    Returns a dict of extracted fields, or None on failure.
    """
    try:
        client = _get_client()
        message = client.messages.create(
            model=model,
            max_tokens=400,
            system=_SYSTEM_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": _USER_PROMPT.format(
                        title=title,
                        description=description[:800],  # cap description length
                    ),
                }
            ],
        )
        raw = message.content[0].text
        return _parse_response(raw)

    except json.JSONDecodeError as e:
        logger.warning("AI response was not valid JSON for '%s': %s", title[:60], e)
        return None
    except Exception as e:
        logger.warning("AI enrichment failed for '%s': %s", title[:60], e)
        return None


def _dict_to_incident(data: dict[str, Any]) -> IncidentDetail:
    """Convert AI response dict to an IncidentDetail dataclass."""
    is_fixed = data.get("is_fixed")
    if isinstance(is_fixed, str):
        is_fixed = is_fixed.lower() == "true" if is_fixed.lower() in ("true", "false") else None

    return IncidentDetail(
        incident_type=data.get("incident_type") or "Security Incident",
        victim=data.get("victim") or "Unknown",
        impact=data.get("impact") or "Not reported",
        root_cause=data.get("root_cause") or "Under investigation",
        is_fixed=is_fixed,
        severity_rationale=data.get("severity_rationale") or "",
        ai_score_boost=float(data.get("ai_score_boost") or 0),
    )


# ── Batch enrichment ──────────────────────────────────────────────────────────

def enrich_items_batch(
    items: list,
    model: str = "claude-haiku-4-5",
    max_workers: int = 5,
    progress_callback=None,
) -> list:
    """
    Enrich a list of NewsItems with AI-extracted incident details.
    Uses a thread pool to parallelize API calls (respects rate limits).
    Falls back to heuristic extraction for any item that fails.

    Args:
        items: list of NewsItem
        model: Anthropic model to use
        max_workers: parallel API calls (keep ≤5 to avoid rate limits)
        progress_callback: optional callable(completed, total) for progress

    Returns:
        The same list with item.incident populated for each item.
    """
    from secnews.core.incident import extract_incident

    total = len(items)
    completed = 0

    def _enrich_one(item):
        result = enrich_item(item.title, item.description, model=model)
        if result:
            incident = _dict_to_incident(result)
            # Apply AI score boost
            item.score = min(item.score + incident.ai_score_boost, 100.0)
            item.incident = incident
        else:
            # Fallback to heuristic
            item.incident = extract_incident(item.title, item.description)
        return item

    enriched = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_enrich_one, item): item for item in items}
        for future in as_completed(futures):
            try:
                enriched.append(future.result())
            except Exception as e:
                item = futures[future]
                logger.warning("Enrichment failed for '%s': %s", item.title[:60], e)
                item.incident = extract_incident(item.title, item.description)
                enriched.append(item)
            completed += 1
            if progress_callback:
                progress_callback(completed, total)

    # Re-sort by score (AI boost may have changed ordering)
    enriched.sort(key=lambda i: -i.score)
    return enriched
