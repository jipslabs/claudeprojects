"""Rich-based terminal display for the --incidents digest."""

from __future__ import annotations

from datetime import datetime, timezone

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich import box

from secnews.core.models import NewsItem
from secnews.core.incident import IncidentDetail, extract_incident

console = Console()

_FIXED_STYLE = {
    True: ("YES — Patch Available", "bold green"),
    False: ("NO  — No Fix / Actively Exploited", "bold red"),
    None: ("Unknown", "dim yellow"),
}

_TYPE_ICONS = {
    "Ransomware": "🔒",
    "Data Breach": "💾",
    "Supply Chain Attack": "📦",
    "Phishing": "🎣",
    "Zero-Day Exploit": "💥",
    "DDoS Attack": "🌊",
    "Nation-State / APT": "🕵",
    "Authentication Bypass": "🔓",
    "Remote Code Execution": "⚡",
    "Privilege Escalation": "⬆",
    "SQL Injection": "💉",
    "Cross-Site Scripting": "🕸",
    "Malware": "🦠",
    "Vulnerability": "🔍",
    "Security Breach": "🚨",
    "Service Disruption": "⛔",
    "Cryptojacking": "⛏",
}


def _format_age(item: NewsItem) -> str:
    now = datetime.now(timezone.utc)
    age = item.age_hours(now)
    if age < 1:
        return f"{int(age * 60)}m ago"
    if age < 24:
        return f"{age:.0f}h ago"
    return f"{age / 24:.0f}d ago"


def _score_style(score: float) -> str:
    if score >= 80:
        return "bold red"
    if score >= 60:
        return "bold yellow"
    if score >= 40:
        return "yellow"
    return "dim"


def _build_incident_panel(item: NewsItem, idx: int) -> Panel:
    """Render a single incident as a structured Rich Panel."""
    inc: IncidentDetail = item.incident or extract_incident(item.title, item.description)

    icon = _TYPE_ICONS.get(inc.incident_type, "⚠")
    fixed_label, fixed_style = _FIXED_STYLE[inc.is_fixed]

    # Panel title line
    title_text = Text()
    title_text.append(f" #{idx}  ", style="bold white on dark_blue")
    title_text.append(f" {icon} {inc.incident_type}  ", style="bold cyan")
    title_text.append(f"Score: {item.score:.0f}", style=_score_style(item.score))
    title_text.append(f"  {_format_age(item)}", style="dim")

    # Build the structured table
    table = Table(
        box=box.SIMPLE,
        show_header=False,
        padding=(0, 1),
        expand=True,
    )
    table.add_column("Field", style="bold dim", width=18, no_wrap=True)
    table.add_column("Value", style="white")

    # 1. What was the incident?
    table.add_row(
        "What happened",
        Text(item.title, style="bold"),
    )

    # 2. Which company/product?
    victim_text = Text()
    victim_text.append(inc.victim, style="bold yellow" if inc.victim != "Unknown" else "dim")
    if item.cve_ids:
        victim_text.append("  ")
        for cve in item.cve_ids[:3]:
            victim_text.append(f"[{cve}]", style="cyan")
    table.add_row("Who was affected", victim_text)

    # 3. What was the impact?
    table.add_row(
        "Impact",
        Text(
            inc.impact,
            style="bold red" if inc.impact not in ("Not reported", "Unknown") else "dim",
        ),
    )

    # 4. Root cause
    table.add_row(
        "Root cause",
        Text(inc.root_cause, style="white"),
    )

    # 5. Is it fixed?
    table.add_row(
        "Fixed?",
        Text(fixed_label, style=fixed_style),
    )

    # Source + URL row
    source_text = Text()
    source_text.append(item.source_name, style="dim")
    source_text.append("  →  ", style="dim")
    source_text.append(item.url[:100], style="dim blue underline")
    table.add_row("Source", source_text)

    # Optional description snippet
    if item.description and len(item.description) > 20:
        snippet = item.description[:350].rstrip()
        if len(item.description) > 350:
            snippet += "..."
        table.add_row("Details", Text(snippet, style="dim italic"))

    border_color = "red" if inc.is_fixed is False else "blue" if inc.is_fixed else "yellow"
    return Panel(table, title=title_text, border_style=border_color, padding=(0, 1))


def print_incidents_header(days: int, total_items: int, total_sources: int) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    title = Text()
    title.append("  secnews  ", style="bold white on dark_blue")
    title.append("  Cyber Incident Report", style="bold red")
    title.append(f"  — {now}", style="bold")

    stats = (
        f"Look-back: {days} days  |  "
        f"Incidents: {total_items}  |  "
        f"Sources: {total_sources}"
    )
    console.print()
    console.print(Panel(title, subtitle=stats, border_style="red", padding=(0, 2)))
    console.print()


def print_legend() -> None:
    legend = Text()
    legend.append("Border color: ", style="dim")
    legend.append("■ Red", style="bold red")
    legend.append(" = No fix/actively exploited  ", style="dim")
    legend.append("■ Blue", style="bold blue")
    legend.append(" = Fix available  ", style="dim")
    legend.append("■ Yellow", style="bold yellow")
    legend.append(" = Fix status unknown", style="dim")
    console.print(legend)
    console.print()


def print_incidents_digest(
    items: list[NewsItem],
    days: int,
    total_raw: int,
    source_names: list[str],
) -> None:
    """Render the full incident digest."""
    print_incidents_header(days, len(items), len(source_names))

    if not items:
        console.print("[yellow]No incidents found matching your criteria.[/yellow]")
        return

    print_legend()

    for idx, item in enumerate(items, start=1):
        panel = _build_incident_panel(item, idx)
        console.print(panel)
        console.print()

    console.print(Rule(style="dim"))
    console.print(
        f"[dim]  {len(items)} incidents shown · {total_raw} fetched · "
        f"{total_raw - len(items)} filtered  |  "
        f"Run [bold]secnews --incidents --help[/bold] for options[/dim]"
    )
    console.print()
