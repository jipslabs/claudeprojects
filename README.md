# secnews — Security News Aggregator & Digest

> A Python CLI tool that pulls from 15+ cybersecurity sources, deduplicates overlapping stories, clusters them by topic, and surfaces a ranked digest in your terminal — giving you a 5-minute briefing instead of an hour of tab-switching.

---

## What It Does

`secnews` has two modes:

| Mode | Command | What you get |
|------|---------|--------------|
| **News Digest** | `secnews` | Ranked, deduplicated headlines from CVE feeds, blogs, threat intel, HackerNews, Reddit — grouped by topic |
| **Incident Report** | `secnews --incidents` | Structured breach/attack cards for the last 14 days — each showing what happened, who was hit, impact, root cause, and fix status |

---

## Quick Start

### Requirements

- Python 3.10 or higher
- pip
- Internet connection (fetches live feeds)

### Install

```bash
# 1. Clone the repo
git clone https://github.com/jipslabs/claudeprojects.git
cd claudeprojects/cyberbulletin

# 2. Install the package
pip install -e .

# 3. Confirm the CLI is available
secnews --help
```

> **Tip:** Use a virtual environment to keep dependencies isolated:
> ```bash
> python3 -m venv .venv && source .venv/bin/activate
> pip install -e .
> ```

---

## Usage

### News Digest Mode (default)

```bash
secnews
```

Fetches all sources for the last 24 hours, deduplicates, scores, clusters by topic, and prints a ranked terminal digest.

```
╭──────────────────────────────────────────────────────────────╮
│    secnews    Security Digest — 2026-02-21 07:00 UTC         │
╰──────── Look-back: 24h  |  Items: 32  |  Sources: 12 ────────╯

──── Ransomware  [ransomware · healthcare · encryption]  (3 items) ────
 CRITICAL  [ 87] LockBit affiliate hits Ascension Health for 3rd time  (4h ago)
 HIGH      [ 71] Ransomware group publishes stolen hospital patient data  (8h ago)
...
```

#### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--hours N` | `24` | Look-back window in hours |
| `--min-score N` | `40` | Minimum relevance score (0–100) to include |
| `--filter KEYWORD` | — | Free-text filter on titles and descriptions |
| `--sources CATS` | all | Comma-separated categories: `cve,blogs,community,advisories,threat_intel,incidents` |
| `--verbose` | off | Show full descriptions and clickable source URLs |
| `--config PATH` | auto | Path to a custom `config.yaml` |
| `--debug` | off | Show which sources succeeded/failed and item counts |

#### Examples

```bash
# Last 48 hours of news
secnews --hours 48

# Only high-confidence items
secnews --min-score 60

# Filter to a specific topic
secnews --filter "supply chain"

# Only CVE feeds and vendor advisories
secnews --sources cve,advisories

# Full details with URLs (good for piping to a file)
secnews --verbose > briefing.txt

# Combine flags
secnews --hours 12 --min-score 70 --filter "zero-day" --verbose
```

---

### Incident Report Mode

```bash
secnews --incidents
```

Switches to a **structured incident report** view. Looks back **14 days** by default and scans incident-focused sources. Each result is rendered as a structured card answering five key questions:

```
╭──────────────────────────────────────────────────────────────╮
│    secnews    Cyber Incident Report  — 2026-02-21 07:00 UTC  │
╰────── Look-back: 14 days  |  Incidents: 18  |  Sources: 8 ───╯

┌─ #1  🔒 Ransomware  Score: 91  4d ago ──────────────────────┐
│  What happened    MGM Resorts confirms ransomware attack      │
│  Who was affected MGM Resorts International                   │
│  Impact           Systems encrypted; hotel check-in disrupted │
│  Root cause       Social engineering / help-desk impersonation│
│  Fixed?           NO — No Fix / Actively Exploited            │
│  Source           BleepingComputer → https://...              │
└──────────────────────────────────────────────────────────────┘
```

**Border color legend:**
- 🔴 **Red border** — No patch / actively exploited
- 🔵 **Blue border** — Patch or fix available
- 🟡 **Yellow border** — Fix status unknown

#### What each field means

| Field | Description |
|-------|-------------|
| **What happened** | The headline — the incident in one line |
| **Who was affected** | Company name, product, or service that was breached or attacked |
| **Impact** | Records stolen, services disrupted, financial damage, or "Not reported" if not disclosed |
| **Root cause** | CVE ID, attack vector (phishing, misconfiguration, credential theft), or "Under investigation" |
| **Fixed?** | Whether a patch, workaround, or remediation is publicly available |

#### Incident mode options

| Flag | Default | Description |
|------|---------|-------------|
| `--incidents` | — | Enable incident report mode |
| `--days N` | `14` | Look-back window in days |
| `--filter KEYWORD` | — | Filter to incidents mentioning a specific company, CVE, or attack type |
| `--min-score N` | `40` | Minimum relevance score |
| `--sources CATS` | auto | Override which source categories to query |

#### Incident mode examples

```bash
# 14-day incident report (default)
secnews --incidents

# Last 7 days only
secnews --incidents --days 7

# Incidents involving a specific company
secnews --incidents --filter Microsoft

# Ransomware incidents only
secnews --incidents --filter ransomware

# High-severity incidents only
secnews --incidents --min-score 65

# Data breaches involving a specific CVE
secnews --incidents --filter CVE-2024

# Save the report to a file
secnews --incidents > incident-report-$(date +%F).txt
```

---

## Scoring System

Every item gets a **relevance score from 0 to 100** based on:

| Factor | Weight | Notes |
|--------|--------|-------|
| CVSS score | 30% | CVSSv3/v4 base score mapped to 0–30 |
| Recency | 25% | Exponential decay — halves every 12 hours |
| Source tier | 20% | Tier 1 (NVD, CISA, Krebs) > Tier 2 > Tier 3 |
| HN engagement | 10% | Log-scaled HackerNews upvotes |
| Watchlist hits | 15% | Matches against your personal watchlist in `config.yaml` |

Scores are shown in brackets next to each item: `[ 87]` = very high signal, `[ 40]` = threshold minimum.

---

## Data Sources

### CVE & Vulnerability Feeds
| Source | Type | Tier |
|--------|------|------|
| NVD CVE API v2 | JSON API | 1 |
| OSV.dev (7 ecosystems: PyPI, npm, Go, Maven, RubyGems, crates.io, NuGet) | GCS Zip | 1 |

### Security Blogs
| Source | Type | Tier |
|--------|------|------|
| Krebs on Security | RSS | 1 |
| SANS Internet Storm Center | RSS | 1 |
| Schneier on Security | RSS | 2 |

### Vendor Advisories
| Source | Type | Tier |
|--------|------|------|
| CISA Known Exploited Vulnerabilities (KEV) | JSON | 1 |
| Google Project Zero | Atom | 1 |
| US-CERT CISA Alerts | RSS | 1 |

### Community
| Source | Type | Tier |
|--------|------|------|
| HackerNews (security-filtered) | Firebase API | 2 |
| Reddit r/netsec | RSS | 2 |
| Reddit r/cybersecurity | RSS | 3 |

### Threat Intel
| Source | Type | Tier |
|--------|------|------|
| The Hacker News | RSS | 2 |
| BleepingComputer | RSS | 2 |
| SecurityWeek | RSS | 2 |
| Threatpost | RSS | 2 |
| AlienVault OTX | RSS | 2 |
| Dark Reading | RSS | 3 |

### Incident-Focused (used in `--incidents` mode)
| Source | Type | Tier |
|--------|------|------|
| DataBreaches.net | RSS | 1 |
| The Record (Recorded Future News) | RSS | 1 |
| CyberScoop | RSS | 2 |
| SC Media | RSS | 2 |

---

## Configuration

`config.yaml` in the project root controls everything. The tool auto-detects it when run from the project directory. You can also point to a custom config with `--config PATH`.

### Watchlist keywords

Add terms relevant to your environment — items matching these get a score boost:

```yaml
watchlist:
  - ransomware
  - zero-day
  - your-product-name    # e.g. "Okta", "Splunk", "Jenkins"
  - your-vendor-name
  - CVE-2024-12345       # specific CVE you're tracking
```

### Adjust scoring weights

```yaml
scoring:
  cvss_weight: 30        # CVSS base score contribution (0-30 points)
  recency_weight: 25     # Recency decay contribution (0-25 points)
  source_tier_weight: 20 # Source quality contribution (0-20 points)
  engagement_weight: 10  # HackerNews upvotes contribution (0-10 points)
  watchlist_weight: 15   # Watchlist keyword match contribution (0-15 points)
```

### Enable/disable individual sources

```yaml
sources:
  blogs:
    - name: Schneier on Security
      type: rss
      url: https://www.schneier.com/feed/atom
      tier: 2
      enabled: false    # set to false to skip this source
```

---

## Scheduling (Daily Briefing via cron)

```bash
crontab -e
```

Add one of these lines (adjust the path from `which secnews`):

```bash
# 7am daily news digest
0 7 * * * /usr/local/bin/secnews --min-score 50 >> ~/secnews-daily.log 2>&1

# 7am 14-day incident report, high-severity only
0 7 * * * /usr/local/bin/secnews --incidents --min-score 60 >> ~/incidents.log 2>&1

# Monday morning weekly recap (last 7 days)
0 8 * * 1 /usr/local/bin/secnews --incidents --days 7 > ~/weekly-incidents-$(date +\%F).txt
```

---

## Project Structure

```
cyberbulletin/
├── config.yaml                    # Sources, watchlist, scoring weights
├── pyproject.toml                 # Package metadata and CLI entry point
├── requirements.txt               # Dependencies
│
├── secnews/
│   ├── cli/
│   │   ├── main.py                # CLI entrypoint — digest and incident modes
│   │   ├── display.py             # Rich digest renderer (news mode)
│   │   └── incident_display.py    # Rich incident card renderer (--incidents mode)
│   │
│   ├── core/
│   │   ├── models.py              # NewsItem + Cluster dataclasses
│   │   ├── dedup.py               # SHA-256 fingerprint + rapidfuzz fuzzy dedup
│   │   ├── cluster.py             # Union-find keyword-based topic clustering
│   │   ├── scorer.py              # Heuristic 0–100 scoring engine
│   │   ├── keywords.py            # Keyword extraction (CVEs, actors, products)
│   │   └── incident.py            # Heuristic incident field extractor
│   │
│   └── sources/
│       ├── fetcher.py             # ThreadPoolExecutor parallel dispatcher
│       ├── rss.py                 # RSS/Atom feed parser
│       ├── nvd.py                 # NVD CVE API v2 ingester
│       ├── osv.py                 # OSV.dev GCS zip ingester (7 ecosystems)
│       ├── hn.py                  # HackerNews Firebase API (security-filtered)
│       ├── cisa.py                # CISA KEV JSON catalog ingester
│       └── json_feed.py           # Generic JSON feed fallback
│
└── tests/
    ├── test_dedup.py
    ├── test_scorer.py
    └── test_cluster.py
```

---

## Development

### Run tests

```bash
pip install -e ".[dev]"
pytest
pytest -v           # verbose
pytest --tb=short   # shorter tracebacks
```

### Dependencies

| Package | Purpose |
|---------|---------|
| `feedparser` | RSS/Atom feed parsing |
| `requests` | HTTP fetching |
| `rapidfuzz` | Fuzzy string deduplication |
| `rich` | Terminal rendering |
| `pyyaml` | Config file parsing |

---

## Known Limitations

- **Incident field extraction** (root cause, impact, victim) is heuristic — works well on well-structured headlines but may show "Unknown" on vague articles.
- **AlienVault OTX** subscribed feed requires a free account for full access; anonymous access may return limited results.
- **Reddit** occasionally rate-limits anonymous RSS — the tool skips gracefully without crashing.
- **CISA KEV** only lists vulnerabilities *added* to the catalog in the look-back window, not the full catalog.
- **Google Project Zero** posts a few times per month — expect 0 results on most days.
- All fetching is **read-only** — no accounts, no active scanning, no data stored.

---

## License

MIT — free to use, modify, and distribute.
