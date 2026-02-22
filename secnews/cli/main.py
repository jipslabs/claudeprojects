"""CLI entrypoint for secnews."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path


def _default_config() -> str:
    """Return path to config.yaml, searching common locations."""
    candidates = [
        Path.cwd() / "config.yaml",
        Path.home() / ".config" / "secnews" / "config.yaml",
        Path(__file__).parent.parent.parent / "config.yaml",
    ]
    for p in candidates:
        if p.exists():
            return str(p)
    return str(candidates[0])  # fallback — will error with a clear message


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secnews",
        description=(
            "Security News Aggregator & Digest — "
            "fetch, deduplicate, cluster, and score cybersecurity news."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  secnews                          # Default 24h digest
  secnews --hours 48               # Last 48 hours
  secnews --min-score 60           # High-signal items only
  secnews --filter ransomware      # Filter by keyword
  secnews --sources cve,advisories # Only CVE and advisory sources
  secnews --verbose                # Full descriptions + URLs
        """,
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=24,
        metavar="N",
        help="Look-back window in hours (default: 24)",
    )
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
        "--sources",
        type=str,
        default=None,
        metavar="CATEGORY",
        help="Comma-separated source categories: cve,blogs,community,advisories,threat_intel",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show full descriptions and source URLs",
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
    return parser


def run() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Logging setup
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

    # Lazy imports after arg parsing (faster --help)
    from rich.console import Console
    from rich.status import Status

    from secnews.core.cluster import cluster_items
    from secnews.core.dedup import deduplicate
    from secnews.core.scorer import score_all
    from secnews.sources.fetcher import fetch_all, load_config
    from secnews.cli.display import print_digest

    console = Console()

    config = load_config(config_path)

    source_filter = (
        [s.strip() for s in args.sources.split(",")]
        if args.sources
        else None
    )

    max_workers = config.get("fetch", {}).get("max_workers", 20)
    dedup_threshold = config.get("dedup", {}).get("similarity_threshold", 85)

    with Status("[bold blue]Fetching security feeds...[/bold blue]", console=console):
        raw_items = fetch_all(
            config,
            hours=args.hours,
            source_filter=source_filter,
            max_workers=max_workers,
        )

    total_raw = len(raw_items)

    with Status("[bold blue]Deduplicating...[/bold blue]", console=console):
        items = deduplicate(raw_items, similarity_threshold=dedup_threshold)

    with Status("[bold blue]Scoring...[/bold blue]", console=console):
        items = score_all(items, config)

    # Apply filters
    if args.filter:
        kw = args.filter.lower()
        items = [
            i for i in items
            if kw in i.title.lower() or kw in i.description.lower()
        ]

    items = [i for i in items if i.score >= args.min_score]

    with Status("[bold blue]Clustering...[/bold blue]", console=console):
        clusters = cluster_items(items)

    source_names = list({i.source_name for i in raw_items})

    print_digest(
        clusters,
        verbose=args.verbose,
        hours=args.hours,
        total_raw=total_raw,
        source_names=source_names,
    )


def main() -> None:
    try:
        run()
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
