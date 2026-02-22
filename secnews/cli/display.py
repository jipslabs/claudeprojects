"""Rich-based terminal display for the digest."""

from __future__ import annotations

from datetime import datetime, timezone

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from secnews.core.models import Cluster, NewsItem

console = Console()

# Score → color mapping
_SCORE_COLORS = {
    80: "bold red",
    60: "bold yellow",
    40: "yellow",
    0: "dim white",
}


def _score_color(score: float) -> str:
    for threshold, color in sorted(_SCORE_COLORS.items(), reverse=True):
        if score >= threshold:
            return color
    return "dim white"


def _severity_badge(item: NewsItem) -> Text:
    """Return a colored severity badge based on CVSS or score."""
    cvss = item.cvss_score
    if cvss is not None:
        if cvss >= 9.0:
            return Text(" CRITICAL ", style="bold white on red")
        if cvss >= 7.0:
            return Text(" HIGH     ", style="bold white on dark_orange")
        if cvss >= 4.0:
            return Text(" MEDIUM   ", style="bold black on yellow")
        return Text(" LOW      ", style="bold black on green")
    if item.score >= 70:
        return Text(" HIGH     ", style="bold white on dark_orange")
    if item.score >= 40:
        return Text(" MEDIUM   ", style="bold black on yellow")
    return Text(" INFO     ", style="dim")


def _format_age(item: NewsItem) -> str:
    now = datetime.now(timezone.utc)
    age = item.age_hours(now)
    if age < 1:
        return f"{int(age * 60)}m ago"
    if age < 24:
        return f"{age:.0f}h ago"
    return f"{age / 24:.0f}d ago"


def _item_row(item: NewsItem, verbose: bool) -> Text:
    t = Text()
    t.append(_severity_badge(item))
    t.append(f" [{item.score:4.0f}] ", style=_score_color(item.score))
    t.append(item.title, style="bold")
    t.append(f"  ({_format_age(item)})", style="dim")

    if item.cve_ids:
        t.append("  ")
        for cve in item.cve_ids[:3]:
            t.append(f"[{cve}]", style="cyan")

    if item.duplicate_sources:
        t.append(f"  also: {', '.join(item.duplicate_sources[:3])}", style="dim italic")

    if verbose:
        t.append("\n")
        t.append(f"  Source : {item.source_name} ({item.source_category})\n", style="dim")
        t.append(f"  URL    : {item.url}\n", style="dim blue underline")
        if item.description:
            desc = item.description[:300] + ("..." if len(item.description) > 300 else "")
            t.append(f"  {desc}\n", style="dim")

    return t


def print_header(hours: int, total_items: int, total_sources_hit: int) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    title = Text()
    title.append("  secnews  ", style="bold white on dark_blue")
    title.append(f"  Security Digest — {now}", style="bold")

    stats = (
        f"Look-back: {hours}h  |  "
        f"Items: {total_items}  |  "
        f"Sources: {total_sources_hit}"
    )

    console.print()
    console.print(Panel(title, subtitle=stats, border_style="blue", padding=(0, 2)))
    console.print()


def print_cluster(cluster: Cluster, verbose: bool, show_all: bool) -> None:
    is_other = cluster.name == "Other"

    # Cluster header
    kw_str = ""
    if cluster.shared_keywords:
        kw_str = "  [" + " · ".join(cluster.shared_keywords[:4]) + "]"

    header = Text()
    if is_other:
        header.append("  Unclustered Items", style="bold dim")
    else:
        header.append(f"  {cluster.name}", style="bold cyan")
        header.append(kw_str, style="dim cyan")
        header.append(f"  ({len(cluster.items)} items)", style="dim")

    console.print(Rule(header, style="blue" if not is_other else "dim"))

    items_to_show = cluster.items if show_all else cluster.items[:5]

    for item in items_to_show:
        console.print(_item_row(item, verbose), highlight=False)
        if verbose:
            console.print()

    if not show_all and len(cluster.items) > 5:
        console.print(
            f"  [dim]... and {len(cluster.items) - 5} more. Use --verbose to expand.[/dim]"
        )

    console.print()


def print_digest(
    clusters: list[Cluster],
    verbose: bool,
    hours: int,
    total_raw: int,
    source_names: list[str],
) -> None:
    total_items = sum(len(c.items) for c in clusters)
    print_header(hours, total_items, len(source_names))

    if not clusters:
        console.print("[yellow]No items found matching your criteria.[/yellow]")
        return

    for cluster in clusters:
        print_cluster(cluster, verbose=verbose, show_all=verbose)

    # Footer summary
    console.print(Rule(style="dim"))
    console.print(
        f"[dim]  {total_items} items shown · {total_raw} fetched · "
        f"{total_raw - total_items} deduplicated/filtered  |  "
        f"Run [bold]secnews --help[/bold] for options[/dim]"
    )
    console.print()
