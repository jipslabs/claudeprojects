"""CLI entrypoint for secnews."""

__author__ = "Jiphun Satapathy"

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

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
            "Use --incidents for a structured breach/incident report view.\n"
            "Add --ai to enrich incidents with Claude Haiku (requires ANTHROPIC_API_KEY)."
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

  secnews --incidents                  # Structured 14-day incident report (heuristic)
  secnews --incidents --ai             # Same, but fields extracted by Claude Haiku
  secnews --incidents --days 7         # Incidents from last 7 days
  secnews --incidents --ai --filter Apple  # AI-enhanced, filtered to Apple incidents

Environment variables:
  ANTHROPIC_API_KEY   Required for --ai mode (get one at console.anthropic.com)
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
            "Structured incident report mode. Shows: what happened, who was affected, "
            "impact, root cause, and fix status. Default look-back is 14 days."
        ),
    )
    parser.add_argument(
        "--days",
        type=int,
        default=14,
        metavar="N",
        help="Look-back window in days for --incidents mode (default: 14)",
    )

    # ── AI enrichment flag ────────────────────────────────────────────────────
    parser.add_argument(
        "--ai",
        action="store_true",
        help=(
            "Enable Claude Haiku AI enrichment for incident field extraction. "
            "Requires ANTHROPIC_API_KEY environment variable. "
            "Significantly improves accuracy of victim, impact, root cause, and fix status. "
            "Cost: ~$0.001 per incident (~$0.05 for a typical 50-item report)."
        ),
    )
    parser.add_argument(
        "--ai-model",
        type=str,
        default=None,
        metavar="MODEL",
        help="Override the AI model (default: from config.yaml or claude-haiku-4-5)",
    )

    return parser


def _is_incident_related(item) -> bool:
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

    # ── AI mode validation ────────────────────────────────────────────────────
    if args.ai:
        from secnews.core.ai_enricher import is_available
        if not is_available():
            import os
            if not os.environ.get("ANTHROPIC_API_KEY"):
                console.print(
                    "\n[bold red]ERROR:[/bold red] --ai requires the ANTHROPIC_API_KEY "
                    "environment variable.\n"
                    "  Get a key at: [blue underline]https://console.anthropic.com[/blue underline]\n"
                    "  Then run:     [bold]export ANTHROPIC_API_KEY=sk-ant-...[/bold]\n"
                )
                sys.exit(1)
            console.print(
                "\n[bold red]ERROR:[/bold red] anthropic package not installed.\n"
                "  Run: [bold]pip install anthropic[/bold]\n"
            )
            sys.exit(1)

    # Resolve AI model: CLI flag > config > default
    ai_config = config.get("ai", {})
    ai_model = args.ai_model or ai_config.get("model", "claude-haiku-4-5")
    ai_max_workers = ai_config.get("max_concurrent_requests", 5)

    # ── Incident mode ─────────────────────────────────────────────────────────
    if args.incidents:
        hours = args.days * 24
        source_filter = (
            [s.strip() for s in args.sources.split(",")]
            if args.sources
            else ["incidents", "threat_intel", "blogs", "advisories", "community"]
        )

        with Status("[bold red]Fetching incident feeds...[/bold red]", console=console):
            raw_items = fetch_all(
                config, hours=hours, source_filter=source_filter,
                max_workers=config.get("fetch", {}).get("max_workers", 20),
            )

        total_raw = len(raw_items)

        with Status("[bold red]Deduplicating...[/bold red]", console=console):
            items = deduplicate(
                raw_items,
                similarity_threshold=config.get("dedup", {}).get("similarity_threshold", 85),
            )

        with Status("[bold red]Scoring...[/bold red]", console=console):
            items = score_all(items, config)

        # Filter to incident-related items
        items = [i for i in items if _is_incident_related(i)]

        if args.filter:
            kw = args.filter.lower()
            items = [i for i in items if kw in i.title.lower() or kw in i.description.lower()]

        items = [i for i in items if i.score >= args.min_score]
        items = sorted(items, key=lambda i: -i.score)

        # ── AI or heuristic enrichment ────────────────────────────────────────
        enrichment_stats = None
        if args.ai:
            from secnews.core.ai_enricher import enrich_items_batch, EnrichmentStats

            total_count = len(items)

            with console.status(
                f"[bold magenta]✦ Claude Haiku extracting incident intelligence "
                f"(0/{total_count})...[/bold magenta]"
            ) as status:
                def _progress(completed, total, stats):
                    status.update(
                        f"[bold magenta]✦ Claude Haiku extracting incident intelligence "
                        f"({completed}/{total})"
                        f"  ✓ AI: {stats.ai_success}  ~ fallback: {stats.heuristic_fallback}"
                        f"[/bold magenta]"
                    )

                items, enrichment_stats = enrich_items_batch(
                    items,
                    model=ai_model,
                    max_workers=ai_max_workers,
                    progress_callback=_progress,
                )

            # Warn clearly if all AI calls failed (key not working, wrong key, etc.)
            if enrichment_stats.all_failed:
                console.print(
                    "\n[bold yellow]⚠  WARNING:[/bold yellow] All Claude API calls failed — "
                    "output is heuristic only.\n"
                    "  Check that your API key is valid:\n"
                    "  [bold]export ANTHROPIC_API_KEY=sk-ant-...[/bold]\n"
                    "  Key set: "
                    + ("[green]Yes[/green]" if os.environ.get("ANTHROPIC_API_KEY") else "[red]No[/red]")
                    + "\n"
                )
            elif enrichment_stats.heuristic_fallback > 0:
                console.print(
                    f"[dim]  ℹ  {enrichment_stats.ai_success} items enriched by Claude · "
                    f"{enrichment_stats.heuristic_fallback} fell back to heuristic[/dim]\n"
                )
        else:
            with Status("[bold red]Extracting incident details (heuristic)...[/bold red]", console=console):
                for item in items:
                    item.incident = extract_incident(item.title, item.description)
                    item.ai_enriched = False

        source_names = list({i.source_name for i in raw_items})
        effective_ai_mode = args.ai and enrichment_stats is not None and not enrichment_stats.all_failed
        print_incidents_digest(
            items,
            days=args.days,
            total_raw=total_raw,
            source_names=source_names,
            ai_mode=effective_ai_mode,
            enrichment_stats=enrichment_stats,
        )

    # ── Standard digest mode ──────────────────────────────────────────────────
    else:
        source_filter = (
            [s.strip() for s in args.sources.split(",")]
            if args.sources
            else None
        )

        with Status("[bold blue]Fetching security feeds...[/bold blue]", console=console):
            raw_items = fetch_all(
                config, hours=args.hours, source_filter=source_filter,
                max_workers=config.get("fetch", {}).get("max_workers", 20),
            )

        total_raw = len(raw_items)

        with Status("[bold blue]Deduplicating...[/bold blue]", console=console):
            items = deduplicate(
                raw_items,
                similarity_threshold=config.get("dedup", {}).get("similarity_threshold", 85),
            )

        with Status("[bold blue]Scoring...[/bold blue]", console=console):
            items = score_all(items, config)

        if args.filter:
            kw = args.filter.lower()
            items = [i for i in items if kw in i.title.lower() or kw in i.description.lower()]

        items = [i for i in items if i.score >= args.min_score]

        with Status("[bold blue]Clustering...[/bold blue]", console=console):
            clusters = cluster_items(items)

        source_names = list({i.source_name for i in raw_items})
        print_digest(
            clusters, verbose=args.verbose, hours=args.hours,
            total_raw=total_raw, source_names=source_names,
        )


def main() -> None:
    try:
        run()
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
