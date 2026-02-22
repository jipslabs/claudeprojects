"""CLI entrypoint for secnews."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Incident-relevant keywords for auto-filtering in --incidents mode
_INCIDENT_KEYWORDS = {
    "breach", "breached", "hacked", "hack", "compromised", "ransomware",
    "attack", "attacked", "stolen", "leaked", "exposed", "exfiltrated",
    "phishing", "malware", "intrusion", "incident", "exploit", "zero-day",
    "0-day", "CVE-", "data leak", "data theft", "unauthorized access",
    "supply chain", "backdoor", "outage", "disrupted", "credential",
    "APT", "nation-state", "espionage", "extortion", "DDoS",
}


def _default_config() -> str:
    candidates = [
        Path.cwd() / "config.yaml",
        Path.home() / ".config" / "secnews" / "config.yaml",
        Path(__file__).parent.parent.parent / "config.yaml",
    ]
    for p in candidates:
        if p.exists():
            return str(p)
    return str(candidates[0])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secnews",
        description=(
            "Security News Aggregator & Digest — "
            "fetch, deduplicate, cluster, and score cybersecurity news.\n"
            "Use --incidents for a structured breach/incident report view."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  secnews                              # Default 24h news digest
  secnews --hours 48                   # Last 48 hours
  secnews --min-score 60               # High-signal items only
  secnews --filter ransomware          # Filter by keyword
  secnews --sources cve,advisories     # Only CVE and advisory sources
  secnews --verbose                    # Full descriptions + URLs

  secnews --incidents                  # Structured 14-day incident report
  secnews --incidents --days 7         # Incidents from last 7 days
  secnews --incidents --filter Apple   # Incidents mentioning Apple
  secnews --incidents --min-score 50   # High-relevance incidents only
        """,
    )

    # ── Shared flags ──────────────────────────────────────────────────────────
    parser.add_argument(
        "--min-score",
        type=float,
        default=40.0,
        metavar="SCORE",
        help="Minimum relevance score 0–100 to include (default: 40)",
    )
    parser.add_argument(
        "--filter",
        type=str,
        default=None,
        metavar="KEYWORD",
        help="Free-text keyword filter on titles and descriptions",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show full descriptions and source URLs (digest mode only)",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        metavar="PATH",
        help="Path to config.yaml (default: auto-detect)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )

    # ── Digest mode flags ─────────────────────────────────────────────────────
    parser.add_argument(
        "--hours",
        type=int,
        default=24,
        metavar="N",
        help="Look-back window in hours for digest mode (default: 24)",
    )
    parser.add_argument(
        "--sources",
        type=str,
        default=None,
        metavar="CATEGORY",
        help=(
            "Comma-separated source categories: "
            "cve,blogs,community,advisories,threat_intel,incidents"
        ),
    )

    # ── Incident mode flags ───────────────────────────────────────────────────
    parser.add_argument(
        "--incidents",
        action="store_true",
        help=(
            "Switch to structured incident report mode. Shows breach/attack "
            "details: what happened, who was affected, impact, root cause, "
            "and fix status. Default look-back is 14 days."
        ),
    )
    parser.add_argument(
        "--days",
        type=int,
        default=14,
        metavar="N",
        help="Look-back window in days for --incidents mode (default: 14)",
    )

    return parser


def _is_incident_related(item) -> bool:
    """Heuristic: is this item likely about an incident/breach?"""
    combined = f"{item.title} {item.description}".lower()
    return any(kw.lower() in combined for kw in _INCIDENT_KEYWORDS)


def run() -> None:
    parser = build_parser()
    args = parser.parse_args()

    log_level = logging.DEBUG if args.debug else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(levelname)s [%(name)s] %(message)s",
    )

    config_path = args.config or _default_config()
    if not Path(config_path).exists():
        print(
            f"[ERROR] Config file not found: {config_path}\n"
            "Copy config.yaml to your working directory or pass --config <path>",
            file=sys.stderr,
        )
        sys.exit(1)

    from rich.console import Console
    from rich.status import Status

    from secnews.core.cluster import cluster_items
    from secnews.core.dedup import deduplicate
    from secnews.core.incident import extract_incident
    from secnews.core.scorer import score_all
    from secnews.sources.fetcher import fetch_all, load_config
    from secnews.cli.display import print_digest
    from secnews.cli.incident_display import print_incidents_digest

    console = Console()
    config = load_config(config_path)

    # ── Incident mode ─────────────────────────────────────────────────────────
    if args.incidents:
        hours = args.days * 24
        # Default to incident + threat_intel + blogs + advisories sources
        source_filter = (
            [s.strip() for s in args.sources.split(",")]
            if args.sources
            else ["incidents", "threat_intel", "blogs", "advisories", "community"]
        )

        with Status("[bold red]Fetching incident feeds (14 days)...[/bold red]", console=console):
            raw_items = fetch_all(config, hours=hours, source_filter=source_filter,
                                  max_workers=config.get("fetch", {}).get("max_workers", 20))

        total_raw = len(raw_items)

        with Status("[bold red]Deduplicating...[/bold red]", console=console):
            items = deduplicate(raw_items,
                                similarity_threshold=config.get("dedup", {}).get("similarity_threshold", 85))

        with Status("[bold red]Scoring...[/bold red]", console=console):
            items = score_all(items, config)

        # Filter to incident-related items only
        items = [i for i in items if _is_incident_related(i)]

        # Apply user keyword filter
        if args.filter:
            kw = args.filter.lower()
            items = [i for i in items if kw in i.title.lower() or kw in i.description.lower()]

        items = [i for i in items if i.score >= args.min_score]
        items = sorted(items, key=lambda i: -i.score)

        # Enrich each item with incident detail extraction
        with Status("[bold red]Extracting incident details...[/bold red]", console=console):
            for item in items:
                item.incident = extract_incident(item.title, item.description)

        source_names = list({i.source_name for i in raw_items})
        print_incidents_digest(items, days=args.days, total_raw=total_raw, source_names=source_names)

    # ── Standard digest mode ──────────────────────────────────────────────────
    else:
        source_filter = (
            [s.strip() for s in args.sources.split(",")]
            if args.sources
            else None
        )

        with Status("[bold blue]Fetching security feeds...[/bold blue]", console=console):
            raw_items = fetch_all(config, hours=args.hours, source_filter=source_filter,
                                  max_workers=config.get("fetch", {}).get("max_workers", 20))

        total_raw = len(raw_items)

        with Status("[bold blue]Deduplicating...[/bold blue]", console=console):
            items = deduplicate(raw_items,
                                similarity_threshold=config.get("dedup", {}).get("similarity_threshold", 85))

        with Status("[bold blue]Scoring...[/bold blue]", console=console):
            items = score_all(items, config)

        if args.filter:
            kw = args.filter.lower()
            items = [i for i in items if kw in i.title.lower() or kw in i.description.lower()]

        items = [i for i in items if i.score >= args.min_score]

        with Status("[bold blue]Clustering...[/bold blue]", console=console):
            clusters = cluster_items(items)

        source_names = list({i.source_name for i in raw_items})
        print_digest(clusters, verbose=args.verbose, hours=args.hours,
                     total_raw=total_raw, source_names=source_names)


def main() -> None:
    try:
        run()
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
