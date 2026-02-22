# secnews — Security News Aggregator & Digest

A Python CLI tool that pulls from 15+ cybersecurity sources, deduplicates overlapping stories, clusters them by topic, and presents a ranked digest in your terminal — giving you a 5-minute briefing instead of an hour of tab-switching.

## Features

- **15+ sources**: NVD CVE API, OSV.dev, CISA KEV, Krebs on Security, SANS ISC, Schneier on Security, HackerNews, Reddit r/netsec, AlienVault OTX, Threatpost, The Hacker News, BleepingComputer, SecurityWeek, Dark Reading, Google Project Zero
- **Deduplication**: Exact fingerprint + fuzzy title matching (rapidfuzz) to surface each story once
- **Topic clustering**: Groups related items by shared keywords (CVE IDs, products, attack types, threat actors)
- **Heuristic scoring (0–100)**: CVSS score, recency decay, source tier, HN engagement, watchlist keyword hits
- **Rich terminal output**: Color-coded severity badges, collapsible clusters, clean digest layout
- **Parallel fetching**: All sources fetched concurrently via `ThreadPoolExecutor` in <30s
- **Configurable**: YAML config for sources, watchlist, and scoring weights

## Installation

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/cyberbulletin.git
cd cyberbulletin

# Install (Python 3.10+ required)
pip install -e .

# Or with pip directly
pip install -r requirements.txt
```

## Usage

```bash
# Default: last 24 hours, min score 40
secnews

# Last 48 hours
secnews --hours 48

# High-signal only
secnews --min-score 60

# Filter by keyword
secnews --filter ransomware

# Only CVE and advisory sources
secnews --sources cve,advisories

# Full descriptions + URLs
secnews --verbose

# Combine flags
secnews --hours 12 --min-score 70 --filter "zero-day" --verbose

# Custom config path
secnews --config /path/to/my-config.yaml
```

## Configuration

Copy and edit `config.yaml` to customize sources, watchlist keywords, and scoring weights:

```yaml
watchlist:
  - ransomware
  - zero-day
  - RCE
  - your-product-name

scoring:
  cvss_weight: 30
  recency_weight: 25
  source_tier_weight: 20
  engagement_weight: 10
  watchlist_weight: 15
```

Sources can be enabled/disabled individually:

```yaml
sources:
  blogs:
    - name: Krebs on Security
      type: rss
      url: https://krebsonsecurity.com/feed/
      tier: 1
      enabled: false   # disable any source
```

## Scheduling with cron

```bash
# Run every morning at 7am, save output to a log
0 7 * * * /usr/local/bin/secnews --min-score 50 >> ~/secnews.log 2>&1
```

## Architecture

```
secnews/
├── cli/
│   ├── main.py          # argparse entrypoint
│   └── display.py       # Rich terminal rendering
├── core/
│   ├── models.py        # NewsItem, Cluster dataclasses
│   ├── dedup.py         # Fingerprint + fuzzy deduplication
│   ├── cluster.py       # Keyword-based topic clustering
│   ├── scorer.py        # Heuristic 0–100 scoring
│   └── keywords.py      # Keyword extraction
└── sources/
    ├── fetcher.py        # Parallel dispatch orchestrator
    ├── rss.py            # RSS/Atom feed parser
    ├── nvd.py            # NVD CVE API v2
    ├── osv.py            # OSV.dev API
    ├── hn.py             # HackerNews Firebase API
    ├── cisa.py           # CISA KEV JSON catalog
    └── json_feed.py      # Generic JSON feed fallback
```

## Running Tests

```bash
pip install -e ".[dev]"
pytest
```

## Non-Goals (v1)

- No email delivery, web UI, or persistent history
- No ML classification — heuristic scoring only
- No vulnerability scanning or active probing
- No authentication or user accounts

## License

MIT
