"""Tests for AI enricher — mocks the Anthropic API to avoid real calls."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from secnews.core.ai_enricher import _dict_to_incident, _parse_response, enrich_item
from secnews.core.models import NewsItem


# ── _parse_response tests ─────────────────────────────────────────────────────

def test_parse_clean_json():
    raw = '{"incident_type": "Ransomware", "victim": "MGM", "impact": "Systems encrypted", "root_cause": "Social engineering", "is_fixed": false, "severity_rationale": "Critical breach.", "ai_score_boost": 15}'
    result = _parse_response(raw)
    assert result["incident_type"] == "Ransomware"
    assert result["victim"] == "MGM"
    assert result["is_fixed"] is False


def test_parse_strips_markdown_fences():
    raw = '```json\n{"incident_type": "Data Breach", "victim": "AT&T", "impact": "73 million records", "root_cause": null, "is_fixed": null, "severity_rationale": "Massive breach.", "ai_score_boost": 18}\n```'
    result = _parse_response(raw)
    assert result["incident_type"] == "Data Breach"
    assert result["victim"] == "AT&T"


def test_parse_invalid_json_raises():
    with pytest.raises(json.JSONDecodeError):
        _parse_response("this is not json")


# ── _dict_to_incident tests ───────────────────────────────────────────────────

def test_dict_to_incident_full():
    data = {
        "incident_type": "Zero-Day Exploit",
        "victim": "Apache",
        "impact": "RCE on unpatched servers",
        "root_cause": "CVE-2024-1234",
        "is_fixed": True,
        "severity_rationale": "Widely exploited before patch.",
        "ai_score_boost": 12.0,
    }
    inc = _dict_to_incident(data)
    assert inc.incident_type == "Zero-Day Exploit"
    assert inc.victim == "Apache"
    assert inc.is_fixed is True
    assert inc.ai_score_boost == 12.0
    assert inc.fixed_label == "Yes — patch/fix available"


def test_dict_to_incident_null_fields():
    data = {
        "incident_type": None,
        "victim": None,
        "impact": None,
        "root_cause": None,
        "is_fixed": None,
        "severity_rationale": None,
        "ai_score_boost": None,
    }
    inc = _dict_to_incident(data)
    assert inc.incident_type == "Security Incident"
    assert inc.victim == "Unknown"
    assert inc.impact == "Not reported"
    assert inc.is_fixed is None
    assert inc.ai_score_boost == 0.0


def test_dict_to_incident_string_bool():
    # Claude occasionally returns "true"/"false" as strings
    inc = _dict_to_incident({"is_fixed": "true", "ai_score_boost": 5})
    assert inc.is_fixed is True
    inc2 = _dict_to_incident({"is_fixed": "false", "ai_score_boost": 5})
    assert inc2.is_fixed is False


# ── enrich_item tests (mocked API) ────────────────────────────────────────────

_MOCK_RESPONSE_JSON = {
    "incident_type": "Ransomware",
    "victim": "Change Healthcare",
    "impact": "Pharmacy payment systems disrupted nationwide",
    "root_cause": "ALPHV/BlackCat ransomware via stolen VPN credentials",
    "is_fixed": False,
    "severity_rationale": "Disrupted prescription processing for millions of patients.",
    "ai_score_boost": 18,
}


def _make_mock_client(response_json: dict):
    mock_content = MagicMock()
    mock_content.text = json.dumps(response_json)
    mock_message = MagicMock()
    mock_message.content = [mock_content]
    mock_client = MagicMock()
    mock_client.messages.create.return_value = mock_message
    return mock_client


def test_enrich_item_success():
    with patch("secnews.core.ai_enricher._get_client", return_value=_make_mock_client(_MOCK_RESPONSE_JSON)):
        result = enrich_item(
            title="LockBit ransomware hits Change Healthcare",
            description="Pharmacy payments disrupted nationwide after ransomware attack.",
        )
    assert result is not None
    assert result["incident_type"] == "Ransomware"
    assert result["victim"] == "Change Healthcare"
    assert result["is_fixed"] is False
    assert result["ai_score_boost"] == 18


def test_enrich_item_api_failure_returns_none():
    mock_client = MagicMock()
    mock_client.messages.create.side_effect = Exception("API timeout")
    with patch("secnews.core.ai_enricher._get_client", return_value=mock_client):
        result = enrich_item("Some title", "Some description")
    assert result is None


def test_enrich_item_bad_json_returns_none():
    mock_content = MagicMock()
    mock_content.text = "I cannot process this request."
    mock_message = MagicMock()
    mock_message.content = [mock_content]
    mock_client = MagicMock()
    mock_client.messages.create.return_value = mock_message
    with patch("secnews.core.ai_enricher._get_client", return_value=mock_client):
        result = enrich_item("Some title", "Some description")
    assert result is None


# ── is_available tests ────────────────────────────────────────────────────────

def test_is_available_no_key(monkeypatch):
    from secnews.core import ai_enricher
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert ai_enricher.is_available() is False


def test_is_available_with_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")
    with patch.dict("sys.modules", {"anthropic": MagicMock()}):
        from importlib import reload
        import secnews.core.ai_enricher as ae
        reload(ae)
        assert ae.is_available() is True
