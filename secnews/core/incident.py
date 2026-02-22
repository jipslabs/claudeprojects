"""
Incident detail extractor — heuristic extraction of structured breach/incident
fields from free-text titles and descriptions.

Extracts:
  - incident_type  : ransomware / data breach / vulnerability / DDoS / etc.
  - victim         : company or product name
  - impact         : what was affected (records stolen, services down, etc.)
  - root_cause     : CVE, phishing, misconfiguration, etc.
  - is_fixed       : True / False / None (unknown)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


# ── Incident type patterns ────────────────────────────────────────────────────

_INCIDENT_PATTERNS: list[tuple[str, str]] = [
    (r"ransomware|ransom demand|encrypted files|file-encrypting", "Ransomware"),
    (r"data breach|data leak|data exposed|records exposed|leaked database|database leak", "Data Breach"),
    (r"supply chain|dependency confusion|malicious package|npm package|pypi package|typosquat", "Supply Chain Attack"),
    (r"phishing|spear.?phish|credential harvest|business email compromise|BEC", "Phishing"),
    (r"zero.?day|0.?day", "Zero-Day Exploit"),
    (r"DDoS|distributed denial|denial.of.service", "DDoS Attack"),
    (r"APT|nation.state|state.sponsored|espionage|cyber.espionage", "Nation-State / APT"),
    (r"authentication bypass|auth bypass|login bypass|password bypass", "Authentication Bypass"),
    (r"remote code execution|RCE|arbitrary code", "Remote Code Execution"),
    (r"privilege escalation|privesc|elevated privilege", "Privilege Escalation"),
    (r"sql injection|SQLi", "SQL Injection"),
    (r"cross.site scripting|XSS", "Cross-Site Scripting"),
    (r"cryptojack|cryptomining|coin.?miner", "Cryptojacking"),
    (r"backdoor|trojan|malware|spyware|infostealer|stealer", "Malware"),
    (r"vulnerability|CVE-\d{4}-\d+|flaw|security bug|patch", "Vulnerability"),
    (r"breach|hacked|compromised|intrusion|unauthorized access", "Security Breach"),
    (r"outage|disruption|service.down|unavailable", "Service Disruption"),
]

# ── Impact patterns ────────────────────────────────────────────────────────────

_IMPACT_PATTERNS: list[tuple[str, str]] = [
    (r"(\d[\d,\.]+\s*(?:million|billion|thousand|M|B|K)?\s*(?:records?|users?|accounts?|customers?|individuals?|people)\s*(?:exposed|stolen|leaked|affected|compromised))", "{}"),
    (r"(data of [\d,\.]+ (?:million|billion|thousand|M|B|K)?\s*(?:users?|customers?|people|individuals?))", "{}"),
    (r"(PII|personally identifiable information|SSN|social security|credit card|financial data|health records?|medical records?)\s*(?:exposed|stolen|leaked|compromised)", "{} exposed"),
    (r"(systems?\s+(?:taken offline|shut down|disrupted|encrypted|locked))", "{}"),
    (r"(\$[\d,\.]+(?:\s*(?:million|billion|M|B))?(?:\s*ransom|\s*stolen|\s*lost|\s*in damage)?)", "{}"),
    (r"(production (?:systems?|environment|servers?) (?:down|affected|impacted))", "{}"),
    (r"(source code (?:stolen|exposed|leaked))", "{}"),
    (r"(intellectual property|trade secrets?) (?:stolen|exfiltrated|accessed)", "{} stolen"),
    (r"(no (?:data|customer|user) (?:was )?(?:stolen|exposed|compromised|affected))", "{}"),
]

# ── Root cause patterns ────────────────────────────────────────────────────────

_CAUSE_PATTERNS: list[tuple[str, str]] = [
    (r"(CVE-\d{4}-\d{4,7})", "{}"),
    (r"(misconfigur(?:ed|ation)|exposed\s+(?:S3|bucket|database|API|endpoint|server))", "Misconfiguration — {}"),
    (r"(phishing|spear.?phish)", "Phishing attack"),
    (r"(stolen credentials?|credential stuffing|compromised credentials?|password reuse)", "Compromised credentials"),
    (r"(unpatched|outdated software|legacy system|end.of.life)", "Unpatched/legacy software"),
    (r"(third.party|vendor|supplier|contractor|MSP|managed service)", "Third-party/supply chain compromise"),
    (r"(insider threat|malicious insider|rogue employee)", "Insider threat"),
    (r"(brute.?force|password spray)", "Brute-force attack"),
    (r"(social engineering)", "Social engineering"),
    (r"(zero.?day|0.?day)", "Zero-day vulnerability (unpatched at time of attack)"),
    (r"(SQL injection|XSS|CSRF|RCE|buffer overflow|deserialization)", "Web vulnerability — {}"),
    (r"(default password|default credential)", "Default credentials not changed"),
    (r"(MFA bypass|multi.?factor bypass|OTP bypass)", "MFA bypass"),
]

# ── Fix status patterns ────────────────────────────────────────────────────────

_FIXED_TRUE = re.compile(
    r"patch(?:ed|es|ing)|fix(?:ed|es)|update(?:d|s) available|remediat(?:ed|ion)|"
    r"mitigat(?:ed|ion)|resolved|workaround available|upgrade to|upgrade available|"
    r"version \d[\d\.]+ (?:addresses|fixes|resolves)|security advisory",
    re.IGNORECASE,
)
_FIXED_FALSE = re.compile(
    r"no patch|unpatched|no fix|not yet patched|actively exploited|"
    r"zero.?day|under investigation|ongoing|still vulnerable|no workaround",
    re.IGNORECASE,
)

# ── Victim extraction ──────────────────────────────────────────────────────────

# Well-known company/product names for direct matching
_KNOWN_VICTIMS = [
    "Microsoft", "Google", "Apple", "Meta", "Facebook", "Amazon", "AWS",
    "Cisco", "Fortinet", "Ivanti", "Palo Alto", "CrowdStrike", "SentinelOne",
    "VMware", "Broadcom", "Citrix", "Juniper", "F5", "Check Point",
    "SolarWinds", "Kaseya", "MOVEit", "GoAnywhere", "Progress Software",
    "Atlassian", "Confluence", "Jira", "GitHub", "GitLab", "Bitbucket",
    "Okta", "1Password", "LastPass", "Bitwarden", "Twilio", "Cloudflare",
    "Uber", "Lyft", "Twitter", "X", "LinkedIn", "Slack", "Zoom",
    "Salesforce", "ServiceNow", "SAP", "Oracle", "IBM",
    "NHS", "Change Healthcare", "UnitedHealth", "Ascension",
    "T-Mobile", "AT&T", "Verizon", "Comcast", "Dish Network",
    "MGM", "Caesars", "Casino", "Clorox", "Johnson Controls",
    "Boeing", "Lockheed", "Northrop", "General Electric",
    "Apache", "Log4j", "OpenSSL", "OpenSSH", "curl", "libwebp",
    "WordPress", "Drupal", "Magento", "Shopify",
    "npm", "PyPI", "RubyGems", "crates.io",
]

_KNOWN_VICTIMS_RE = re.compile(
    r"\b(" + "|".join(re.escape(v) for v in _KNOWN_VICTIMS) + r")\b",
    re.IGNORECASE,
)

# Generic victim extraction patterns
_VICTIM_GENERIC = [
    re.compile(r"(?:hack(?:ed|s)|breach(?:ed|es|ing)?|attack(?:ed|s)|hit|target(?:ed|s)|struck|affect(?:ed|s)|compromised)\s+(?:by\s+\w+\s+)?([A-Z][A-Za-z0-9\s&\-']{2,40}?)(?:\s*[,\.;]|\s+(?:systems?|users?|customers?|data|network))", re.IGNORECASE),
    re.compile(r"([A-Z][A-Za-z0-9\s&\-']{2,40}?)\s+(?:confirms?|discloses?|reports?|warns?|reveals?|says?|acknowledges?)\s+(?:a\s+)?(?:data\s+)?breach", re.IGNORECASE),
    re.compile(r"([A-Z][A-Za-z0-9\s&\-']{2,40}?)\s+(?:hit|struck|targeted|crippled|disrupted)\s+by", re.IGNORECASE),
    re.compile(r"vulnerability\s+in\s+([A-Za-z0-9][A-Za-z0-9\s&\-'\.]{1,40}?)(?:\s*[,\.;]|\s+(?:allows?|enables?|could|lets?))", re.IGNORECASE),
    re.compile(r"(?:flaw|bug|issue|vulnerability)\s+(?:found|discovered|identified)\s+in\s+([A-Za-z0-9][A-Za-z0-9\s&\-'\.]{1,40}?)(?:\s*[,\.;])", re.IGNORECASE),
]


@dataclass
class IncidentDetail:
    incident_type: str = "Unknown"
    victim: str = "Unknown"
    impact: str = "Not reported"
    root_cause: str = "Under investigation"
    is_fixed: Optional[bool] = None  # True=fixed, False=not fixed, None=unknown

    @property
    def fixed_label(self) -> str:
        match self.is_fixed:
            case True:
                return "Yes — patch/fix available"
            case False:
                return "No — actively exploited / no patch"
            case _:
                return "Unknown"


def _first_match(patterns: list[tuple[str, str]], text: str) -> str | None:
    for pattern, template in patterns:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            matched = m.group(1) if m.lastindex else m.group(0)
            return template.format(matched.strip()) if "{}" in template else template
    return None


def _extract_victim(text: str) -> str:
    # 1. Known name direct match
    m = _KNOWN_VICTIMS_RE.search(text)
    if m:
        return m.group(1)

    # 2. Generic pattern match
    for pattern in _VICTIM_GENERIC:
        m = pattern.search(text)
        if m:
            candidate = m.group(1).strip().rstrip(".,;'\"")
            # Filter out noise
            if 3 <= len(candidate) <= 60 and not candidate.lower().startswith(
                ("the ", "a ", "an ", "this ", "that ", "its ", "their ")
            ):
                return candidate

    return "Unknown"


def _extract_impact(text: str) -> str:
    for pattern, template in _IMPACT_PATTERNS:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            matched = m.group(1) if m.lastindex else m.group(0)
            result = template.format(matched.strip()) if "{}" in template else template
            return result.strip().capitalize()
    return "Not reported"


def extract_incident(title: str, description: str) -> IncidentDetail:
    """Extract structured incident fields from title + description."""
    combined = f"{title} {description}"

    incident_type = _first_match(_INCIDENT_PATTERNS, combined) or "Security Incident"
    victim = _extract_victim(combined)
    impact = _extract_impact(combined)
    root_cause = _first_match(_CAUSE_PATTERNS, combined) or "Under investigation"

    # Fix status
    is_fixed: Optional[bool] = None
    if _FIXED_TRUE.search(combined):
        is_fixed = True
    if _FIXED_FALSE.search(combined):
        is_fixed = False  # "not fixed" overrides "patch available" in text

    return IncidentDetail(
        incident_type=incident_type,
        victim=victim,
        impact=impact,
        root_cause=root_cause,
        is_fixed=is_fixed,
    )
