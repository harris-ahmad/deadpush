"""
Premium Rich-powered terminal UI for deadpush.

Makes every command feel modern, beautiful, and trustworthy.
Only activated if `rich` is installed (graceful fallback to plain output).
"""

from __future__ import annotations

from typing import Any

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
    from rich.table import Table
    from rich.tree import Tree
    from rich import box
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    Console = None  # type: ignore

from .graph import DeadSymbol, DebrisFile


console = Console() if RICH_AVAILABLE else None


def is_rich_available() -> bool:
    return RICH_AVAILABLE


def print_header(title: str, subtitle: str = "") -> None:
    if not RICH_AVAILABLE:
        print(f"\n=== {title} ===")
        if subtitle:
            print(subtitle)
        return

    panel = Panel(
        f"[bold cyan]{title}[/bold cyan]\n[dim]{subtitle}[/dim]",
        border_style="cyan",
        box=box.ROUNDED,
        padding=(1, 2),
    )
    console.print(panel)


def print_success(message: str) -> None:
    if RICH_AVAILABLE:
        console.print(f"[bold green]✅ {message}[/bold green]")
    else:
        print(f"✅ {message}")


def print_warning(message: str) -> None:
    if RICH_AVAILABLE:
        console.print(f"[bold yellow]⚠️  {message}[/bold yellow]")
    else:
        print(f"⚠️  {message}")


def print_error(message: str) -> None:
    if RICH_AVAILABLE:
        console.print(f"[bold red]❌ {message}[/bold red]")
    else:
        print(f"❌ {message}")


def create_debris_table(debris: list[DebrisFile]) -> Table | str:
    if not RICH_AVAILABLE:
        return "\n".join([f"  - {d.path} ({d.category})" for d in debris])

    table = Table(title="Debris Detected", box=box.ROUNDED, show_lines=True)
    table.add_column("Path", style="cyan", no_wrap=True)
    table.add_column("Category", style="magenta")
    table.add_column("Confidence", justify="right")
    table.add_column("Block Push?", justify="center")
    table.add_column("Suggestion", style="dim")

    for d in debris:
        block_style = "[bold red]YES[/bold red]" if d.block_push else "[green]No[/green]"
        conf = f"{d.confidence * 100:.0f}%"
        table.add_row(
            d.path,
            d.category.replace("_", " ").title(),
            conf,
            block_style,
            d.suggestion[:60] + "..." if len(d.suggestion) > 60 else d.suggestion,
        )
    return table


def create_dead_symbols_tree(dead_symbols: list[DeadSymbol]) -> Tree | str:
    if not RICH_AVAILABLE:
        return f"Found {len(dead_symbols)} dead symbols."

    tree = Tree("[bold red]Dead Code Clusters[/bold red]")

    by_file: dict[str, list[DeadSymbol]] = {}
    for ds in dead_symbols:
        by_file.setdefault(ds.symbol.path, []).append(ds)

    for filepath, symbols in sorted(by_file.items()):
        file_branch = tree.add(f"[cyan]{filepath}[/cyan] ({len(symbols)} symbols)")

        for ds in symbols:
            tier_color = {
                "definite": "red",
                "probable": "yellow",
                "suspicious": "orange1"
            }.get(ds.tier, "white")

            label = (
                f"[{tier_color}]{ds.symbol.name}[/{tier_color}] "
                f"({ds.tier}, {ds.confidence*100:.0f}%)"
            )
            file_branch.add(label)

    return tree


def print_scan_summary(
    total_files: int,
    dead_count: int,
    debris_count: int,
    blocking_debris: int,
    entry_points: int,
) -> None:
    if not RICH_AVAILABLE:
        print(f"\nScan complete: {dead_count} dead | {debris_count} debris ({blocking_debris} blocking)")
        return

    table = Table.grid(padding=(0, 2))
    table.add_row("[bold]Files Scanned[/bold]", str(total_files))
    table.add_row("[bold red]Dead Symbols[/bold red]", str(dead_count))
    table.add_row("[bold yellow]Debris Found[/bold yellow]", f"{debris_count} ({blocking_debris} blocking)")
    table.add_row("[bold green]Entry Points[/bold green]", str(entry_points))

    panel = Panel(table, title="[bold cyan]deadpush Scan Summary[/bold cyan]", border_style="cyan")
    console.print(panel)


def print_blocking_warning(debris: list[DebrisFile]) -> None:
    if not RICH_AVAILABLE:
        print("\nCRITICAL: Blocking debris found!")
        return

    console.print("\n[bold red on white]  🚫 PUSH BLOCKED BY deadpush  [/bold red on white]\n")

    for d in debris:
        if d.block_push:
            console.print(f"[red]• {d.path}[/red] — {d.category}")
            console.print(f"  [dim]{d.suggestion}[/dim]\n")
