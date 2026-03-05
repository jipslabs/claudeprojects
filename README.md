# secnews — Security News Aggregator & Digest

> A Python CLI tool that pulls from 15+ cybersecurity sources, deduplicates overlapping stories, clusters them by topic, and surfaces a ranked digest in your terminal — giving you a 5-minute briefing instead of an hour of tab-switching.

---

## Clone & Test This Service

Two paths depending on whether you have an Anthropic API key. **No subscription is required** for the core service.

---

### ✅ Option A — No Subscription Required (Heuristic Mode)

Everything works out of the box. No API key, no account, no cost.

```bash
# 1. Clone the repo
git clone https://github.com/jipslabs/claudeprojects.git
cd claudeprojects/cyberbulletin

# 2. Create a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate        # macOS/Linux
# .venv\Scripts\activate         # Windows

# 3. Install the package
pip install -e .

# 4. Confirm the CLI is working
secnews --help

# 5. Run the news digest (last 24 hours, all sources)
secnews

# 6. Run the 14-day cyber incident report
secnews --incidents

# 7. Run the unit tests (all 25 should pass)
pip install -e ".[dev]"
pytest
```

> **That's it.** The service will fetch from 15+ live sources, deduplicate, score, cluster, and render everything in your terminal. No API key or account needed.

---

### 🤖 Option B — With Anthropic API Key (AI-Enhanced Mode)

Adds Claude Haiku-powered field extraction on top of everything in Option A. Dramatically improves accuracy for victim identification, impact assessment, and root cause analysis.

**Cost: ~$0.40–$1.57/month** if run daily. Free tier credits are enough to test.

```bash
# 1–4. Follow all steps from Option A above, then continue:

# 5. Install the AI package
pip install -e ".[ai]"

# 6. Get your API key at https://console.anthropic.com → API Keys
#    Then set it in your terminal:
export ANTHROPIC_API_KEY=sk-ant-...

# 7. (Optional) Make it permanent so you don't re-enter it each session:
echo 'export ANTHROPIC_API_KEY=sk-ant-...' >> ~/.zshrc
source ~/.zshrc

# 8. Run the AI-enhanced incident report
secnews --incidents --ai

# 9. Run the unit tests (all 25 should pass, including AI tests which are mocked)
pytest
```

> **Note:** The `--ai` flag gracefully falls back to heuristic mode if the API key is missing or invalid. You'll see a clear warning in the terminal — the report still runs, just without Claude enrichment.

---

### Quick Command Reference

| What you want | Command |
|---|---|
| 24h security news digest | `secnews` |
| 14-day incident report (no API key) | `secnews --incidents` |
| 14-day incident report (AI-enhanced) | `secnews --incidents --ai` |
| Last 7 days, high severity only | `secnews --incidents --days 7 --min-score 65` |
| Filter by company or attack type | `secnews --incidents --filter "ransomware"` |
| Save report to a file | `secnews --incidents --ai > report.txt` |
| Debug — show per-source fetch stats | `secnews --debug` |
| Run tests | `pytest` |

---

## What It Does

`secnews` has two modes, each with optional AI enrichment:

| Mode | Command | What you get |
|------|---------|--------------|
| **News Digest** | `secnews` | Ranked, deduplicated headlines from CVE feeds, blogs, threat intel, HackerNews, Reddit — grouped by topic |
| **Incident Report** | `secnews --incidents` | Structured breach/attack cards for the last 14 days — each showing what happened, who was hit, impact, root cause, and fix status |
| **AI-Enhanced Incidents** | `secnews --incidents --ai` | Same as above, but incident fields extracted by **Claude Haiku** for significantly higher accuracy |

---

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
# 14-day incident report — heuristic extraction (no API key needed)
secnews --incidents

# 14-day incident report — AI-powered extraction via Claude Haiku
secnews --incidents --ai

# Last 7 days, AI-enhanced
secnews --incidents --ai --days 7

# Incidents involving a specific company (AI-enhanced)
secnews --incidents --ai --filter Microsoft

# Ransomware incidents only
secnews --incidents --filter ransomware

# High-severity incidents only
secnews --incidents --min-score 65

# Save the AI report to a file
secnews --incidents --ai > incident-report-$(date +%F).txt
```

---

## AI Enrichment (Claude Haiku)

When you pass `--ai`, each incident card's fields are extracted by **Claude Haiku** instead of regex patterns. This significantly improves accuracy for:

- **Who was affected** — correctly identifies companies even with indirect phrasing (e.g. "a subsidiary of UnitedHealth Group" → `Change Healthcare`)
- **Impact** — extracts quantified damage ("73 million records", "$22M ransom") from anywhere in the article
- **Root cause** — identifies specific CVE IDs, attack chains, and technical mechanisms
- **Fixed?** — correctly handles nuanced language like "a workaround is available but a full patch is pending"
- **AI Analysis** — adds a one-sentence analyst note explaining real-world significance

### AI output example

```
┌─ #1  🔒 Ransomware  Score: 94  ✦ AI  3d ago ──────────────────────┐
│  What happened    Change Healthcare confirms ALPHV ransomware attack │
│  Who was affected Change Healthcare (UnitedHealth Group subsidiary)  │
│  Impact           Pharmacy payment processing disrupted nationwide;  │
│                   patient prescription access affected at 90%+ of US │
│                   pharmacies; $22M ransom reportedly paid            │
│  Root cause       ALPHV/BlackCat ransomware via stolen VPN          │
│                   credentials on Citrix portal lacking MFA           │
│  Fixed?           NO — No Fix / Actively Exploited                  │
│  AI Analysis      Largest healthcare cyberattack in US history;      │
│                   exposed critical dependency on single clearinghouse │
│  Source           BleepingComputer → https://...                    │
└──────────────────────────────────────────────────────────────────────┘
```

### Cost

| Usage | Items/run | Cost/run | Monthly (daily) |
|-------|-----------|----------|-----------------|
| Conservative | 20 | ~$0.013 | ~**$0.40** |
| Typical | 40 | ~$0.026 | ~**$0.79** |
| Heavy | 80 | ~$0.052 | ~**$1.57** |

Model used: `claude-haiku-4-5` at $0.80/M input + $4.00/M output tokens.
Override in `config.yaml` with `ai.model: claude-sonnet-4-5` for higher quality (~10× cost).

### Setup

```bash
# 1. Install anthropic package
pip install -e ".[ai]"

# 2. Set your API key (get one free at console.anthropic.com)
export ANTHROPIC_API_KEY=sk-ant-...

# 3. Run with AI
secnews --incidents --ai
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
├── requirements-lock.txt          # Pinned dependency versions for reproducible installs
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
│   │   ├── incident.py            # Heuristic incident field extractor (fallback)
│   │   └── ai_enricher.py         # Claude Haiku AI enrichment (--ai mode)
│   │
│   └── sources/
│       ├── __init__.py            # Shared http_get() wrapper + URL scheme validator
│       ├── fetcher.py             # ThreadPoolExecutor parallel dispatcher
│       ├── rss.py                 # RSS/Atom feed parser
│       ├── nvd.py                 # NVD CVE API v2 ingester
│       ├── osv.py                 # OSV.dev GCS zip ingester (7 ecosystems)
│       ├── hn.py                  # HackerNews Firebase API (security-filtered)
│       ├── cisa.py                # CISA KEV JSON catalog ingester
│       └── json_feed.py           # Generic JSON feed fallback
│
└── tests/                         # 25 passing unit tests
    ├── test_dedup.py
    ├── test_scorer.py
    ├── test_cluster.py
    └── test_ai_enricher.py        # AI enricher tests (mocked — no real API calls)
```

---

## Development

### Run tests

```bash
pip install -e ".[dev]"
pytest               # 25 tests, all should pass
pytest -v            # verbose output
pytest --tb=short    # shorter tracebacks on failure
```

### Install exact pinned versions (reproducible builds)

```bash
pip install -r requirements-lock.txt
pip install -e .
```

### Dependencies

| Package | Purpose | Required |
|---------|---------|----------|
| `feedparser` | RSS/Atom feed parsing | Always |
| `requests` | HTTP fetching | Always |
| `rapidfuzz` | Fuzzy string deduplication | Always |
| `rich` | Terminal rendering | Always |
| `pyyaml` | Config file parsing | Always |
| `anthropic` | Claude API client for `--ai` mode | Optional (`pip install -e ".[ai]"`) |

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
