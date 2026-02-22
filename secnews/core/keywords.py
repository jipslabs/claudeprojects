"""Keyword extraction for topic clustering."""

from __future__ import annotations

import re

# CVE pattern
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Known threat actors / APT groups
_THREAT_ACTORS = {
    "lazarus", "apt28", "apt29", "cozy bear", "fancy bear", "sandworm",
    "volt typhoon", "salt typhoon", "scattered spider", "lapsus$",
    "cl0p", "lockbit", "blackcat", "alphv", "play", "black basta",
    "rhysida", "akira", "8base", "medusa", "darkside", "revil",
}

# Attack categories
_ATTACK_TYPES = {
    "ransomware", "phishing", "supply chain", "zero-day", "zero day",
    "rce", "remote code execution", "sql injection", "xss", "csrf",
    "privilege escalation", "lateral movement", "credential stuffing",
    "man-in-the-middle", "mitm", "ddos", "dos", "backdoor",
    "rootkit", "keylogger", "spyware", "adware", "trojan", "worm",
    "botnet", "c2", "command and control", "exfiltration",
    "authentication bypass", "path traversal", "lfi", "rfi",
    "deserialization", "buffer overflow", "heap spray",
}

# High-value product/vendor names
_PRODUCTS = {
    "windows", "linux", "macos", "ios", "android",
    "exchange", "outlook", "office", "microsoft", "azure", "active directory",
    "cisco", "juniper", "palo alto", "fortinet", "ivanti", "vmware",
    "apple", "google", "android", "chrome", "firefox", "safari",
    "apache", "nginx", "tomcat", "spring", "log4j", "log4shell",
    "openssl", "openssh", "curl", "libwebp",
    "aws", "gcp", "azure", "kubernetes", "docker",
    "citrix", "pulse secure", "solarwinds", "kaseya",
    "confluence", "jira", "atlassian", "gitlab", "github",
    "wordpress", "drupal", "joomla",
}

# Combine for quick lookup
_ALL_KNOWN = _threat_actors_set = _THREAT_ACTORS | _ATTACK_TYPES | _PRODUCTS


def extract_keywords(text: str) -> list[str]:
    """Extract significant security keywords from text."""
    text_lower = text.lower()
    found: set[str] = set()

    # CVE IDs
    for cve in _CVE_RE.findall(text):
        found.add(cve.upper())

    # Known terms (multi-word first, then single)
    for term in sorted(_ALL_KNOWN, key=len, reverse=True):
        if term in text_lower:
            found.add(term)

    # Generic significant nouns (capitalized, 4+ chars, not all-caps acronyms)
    for word in re.findall(r"\b[A-Z][a-z]{3,}\b", text):
        if word.lower() not in {"this", "that", "with", "from", "have", "been"}:
            found.add(word.lower())

    return list(found)
