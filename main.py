#!/usr/bin/env python3
"""
Device42 fuzzy search across Devices and Assets by hostname, FQDN/alias, or IP.

Usage:
    python main.py web01
    python main.py 10.20.30
    python main.py --json kvm02
    python main.py                 # interactive prompt
"""

from __future__ import annotations

import argparse
import json
import sys

import questionary
from rich.console import Console
from rich.table import Table

from d42.client import Device42Client, Device42Error
from d42.config import load_config
from d42.search import AssetSearcher, InventoryHit

console = Console()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fuzzy search Device42 devices and assets by hostname, FQDN/alias, or IP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("term", nargs="?", help="Search term (hostname, FQDN, or IP)")
    parser.add_argument("--json", action="store_true", help="Print results as JSON")
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Max results (default: config search.limit)",
    )
    parser.add_argument(
        "--pick",
        action="store_true",
        help="Interactive fuzzy pick from results (questionary)",
    )
    return parser.parse_args()


def prompt_term() -> str | None:
    return questionary.text("Search hostname / FQDN / IP:").ask()


def print_table(hits: list[InventoryHit]) -> None:
    table = Table(title=f"Device42 matches ({len(hits)})")
    table.add_column("Kind", style="cyan")
    table.add_column("ID", style="dim")
    table.add_column("Name")
    table.add_column("FQDN")
    table.add_column("IPs")
    table.add_column("Last seen")
    table.add_column("Source")
    table.add_column("Type")
    table.add_column("Matched")
    for hit in hits:
        table.add_row(
            hit.kind,
            str(hit.object_id or ""),
            hit.name,
            hit.fqdn or "-",
            ", ".join(hit.ips) or "-",
            hit.last_seen_label or "-",
            ", ".join(hit.sources) or "-",
            hit.object_type or "-",
            ", ".join(hit.matched_on) or "-",
        )
    console.print(table)


def pick_hit(hits: list[InventoryHit]) -> InventoryHit | None:
    if not hits:
        return None
    if len(hits) == 1:
        return hits[0]
    choice = questionary.select(
        "Select result:",
        choices=[questionary.Choice(title=h.display, value=h) for h in hits[:36]],
    ).ask()
    return choice


def hit_to_dict(hit: InventoryHit) -> dict:
    return {
        "kind": hit.kind,
        "id": hit.object_id,
        "name": hit.name,
        "fqdn": hit.fqdn,
        "ips": hit.ips,
        "aliases": hit.aliases,
        "type": hit.object_type,
        "os_name": hit.os_name,
        "service_level": hit.service_level,
        "in_service": hit.in_service,
        "last_seen": hit.last_seen.isoformat() if hit.last_seen else None,
        "last_seen_label": hit.last_seen_label,
        "sources": hit.sources,
        "matched_on": hit.matched_on,
    }


def main() -> int:
    args = parse_args()
    config = load_config()
    if args.limit:
        config.limit = args.limit

    try:
        client = Device42Client(config)
    except Device42Error as exc:
        console.print(f"[red]Auth failed:[/red] {exc.message}")
        return 1

    searcher = AssetSearcher(client)

    term = args.term
    if not term:
        term = prompt_term()
    if not term:
        return 0

    console.print(f"[cyan]Searching Device42 Devices + Assets for:[/cyan] {term}")
    try:
        hits = searcher.search(term, limit=config.limit)
    except Device42Error as exc:
        console.print(f"[red]Search failed:[/red] {exc.message}")
        return 1

    if not hits:
        console.print("[yellow]No matches[/yellow]")
        return 2

    selected: InventoryHit | None = None
    if args.pick:
        selected = pick_hit(hits)
        if selected is None:
            return 0
        hits = [selected]

    if args.json:
        payload = [hit_to_dict(h) for h in hits]
        print(json.dumps(payload if not args.pick else payload[0], indent=2))
    else:
        print_table(hits)
        if selected:
            console.print(f"[green]Selected:[/green] {selected.display}")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/yellow]")
        sys.exit(130)
