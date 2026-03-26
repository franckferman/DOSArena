#!/usr/bin/env python3
"""
ui/cli.py
DOSArena — Player Terminal Interface

Usage:
  python3 cli.py                     Interactive mode
  python3 cli.py status              Show all scenarios and current state
  python3 cli.py hint 01             Get hint level 1 for scenario 01
  python3 cli.py hint 01 --level 2   Get hint level 2
  python3 cli.py submit 01           Submit flag for scenario 01
  python3 cli.py writeup 01          Show writeup (after solving)
  python3 cli.py scoreboard          Show scoreboard
"""

import sys
import os
import json
import click
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt
from rich import box

JUDGE_URL  = os.environ.get("JUDGE_URL",   "http://10.0.99.30:8888")
PLAYER_ID  = os.environ.get("PLAYER_NAME", "player1")

console = Console()


def _get(path: str) -> dict:
    try:
        r = requests.get(f"{JUDGE_URL}{path}", timeout=5)
        return r.json()
    except Exception as e:
        console.print(f"[red][!] Cannot reach judge: {e}[/red]")
        sys.exit(1)


def _post(path: str, data: dict) -> dict:
    try:
        r = requests.post(f"{JUDGE_URL}{path}", json=data, timeout=5)
        return r.json()
    except Exception as e:
        console.print(f"[red][!] Cannot reach judge: {e}[/red]")
        sys.exit(1)


# ── Commands ────────────────────────────────────────────────────────────────

@click.group()
def cli():
    """DOSArena — DoS/DDoS training lab. Type 'status' to see all targets."""


@cli.command()
def status():
    """Show all scenarios, targets, and current degradation state."""
    data = _get("/status")
    scenarios = data.get("scenarios", {})
    active_flags = data.get("current_flags", {})

    console.print()
    console.print(
        Panel(
            "[bold yellow]DOSArena[/bold yellow] — DoS/DDoS Training Lab\n"
            f"[dim]Judge: {JUDGE_URL}[/dim]",
            border_style="yellow",
        )
    )

    t = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold")
    t.add_column("#",         width=4,  style="dim")
    t.add_column("Scenario",  width=40)
    t.add_column("Target IP", width=14, style="cyan")
    t.add_column("Diff",      width=8)
    t.add_column("Points",    width=7,  style="yellow")
    t.add_column("Status",    width=12)
    t.add_column("Flag",      width=38, style="dim")

    diff_color = {"Easy": "green", "Medium": "yellow", "Hard": "red"}

    for sid, s in sorted(scenarios.items()):
        degraded = s.get("degraded", False)
        flag     = active_flags.get(sid, "")
        status_txt = Text("DEGRADED ✓", style="bold green") if degraded \
            else Text("online",         style="dim")
        d = s.get("difficulty", "?")
        t.add_row(
            sid,
            s["name"],
            s["target_ip"],
            f"[{diff_color.get(d,'white')}]{d}[/{diff_color.get(d,'white')}]",
            str(s["points"]),
            status_txt,
            flag if flag else "",
        )

    console.print(t)
    console.print(
        "[dim]  hint <id>      — get a hint for a scenario[/dim]\n"
        "[dim]  submit <id>    — submit a flag[/dim]\n"
        "[dim]  writeup <id>   — read writeup (after solving)[/dim]\n"
        "[dim]  scoreboard     — show scores[/dim]\n"
    )


@cli.command()
@click.argument("scenario_id")
@click.option("--level", default=1, type=int, help="Hint level (1-3)")
def hint(scenario_id: str, level: int):
    """Get a progressive hint for a scenario."""
    data = _get(f"/hint/{scenario_id}?level={level}")
    if "error" in data:
        console.print(f"[red]{data['error']}[/red]")
        return

    h = data.get("hint")
    max_l = data.get("max_level", 3)
    if not h:
        console.print(f"[yellow]No hint at level {level}. Max level: {max_l}[/yellow]")
        return

    console.print()
    console.print(
        Panel(
            f"[bold]Scenario {scenario_id.upper()} — Hint {level}/{max_l}[/bold]\n\n"
            f"{h}",
            title=f"[yellow]Hint Level {level}[/yellow]",
            border_style="yellow",
        )
    )
    if level < max_l:
        console.print(
            f"[dim]  More specific hint available: "
            f"hint {scenario_id} --level {level+1}[/dim]\n"
        )


@cli.command()
@click.argument("scenario_id")
def submit(scenario_id: str):
    """Submit a flag for a scenario."""
    console.print()
    flag = Prompt.ask(f"[bold]Flag for scenario {scenario_id}[/bold] [dim](DOSARENA{{...}})[/dim]")
    result = _post("/submit", {
        "player":   PLAYER_ID,
        "scenario": scenario_id,
        "flag":     flag.strip(),
    })

    if result.get("ok"):
        console.print(
            Panel(
                f"[bold green]✓ CORRECT[/bold green]\n\n"
                f"{result.get('message', '')}\n"
                f"Total score: [yellow]{result.get('total', 0)}[/yellow] points",
                border_style="green",
            )
        )
    else:
        reason = result.get("reason", "Unknown error")
        console.print(
            Panel(
                f"[bold red]✗ INCORRECT[/bold red]\n\n{reason}",
                border_style="red",
            )
        )
        if "not confirmed" in reason.lower():
            console.print(
                "[yellow]The judge watches targets every 5 seconds.\n"
                "Keep the attack running and try submitting again.[/yellow]\n"
            )


@cli.command()
@click.argument("scenario_id")
def writeup(scenario_id: str):
    """Display full writeup for a solved scenario."""
    # Import writeups from judge directory
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'judge'))
    from writeups import WRITEUPS

    w = WRITEUPS.get(scenario_id)
    if not w:
        console.print(f"[yellow]No writeup available for scenario {scenario_id} yet.[/yellow]")
        return

    console.print()
    console.print(Panel(
        f"[bold]{w['title']}[/bold]\n\n[italic]{w['tldr']}[/italic]",
        title=f"[cyan]Writeup — Scenario {scenario_id}[/cyan]",
        border_style="cyan",
    ))

    sections = [
        ("Vulnerability", "vulnerability"),
        ("Attack Mechanics", "mechanics"),
        ("Real-World Context", "real_world"),
        ("Detection", "detection"),
        ("Mitigation", "mitigation"),
    ]

    for title, key in sections:
        if key in w:
            console.print(f"\n[bold yellow]── {title}[/bold yellow]")
            console.print(w[key].strip())

    if w.get("further_reading"):
        console.print(f"\n[bold yellow]── Further Reading[/bold yellow]")
        for ref in w["further_reading"]:
            console.print(f"  • {ref}")

    console.print()


@cli.command()
def scoreboard():
    """Show the current scoreboard."""
    data = _get("/scoreboard")
    board = data.get("scoreboard", [])

    console.print()
    t = Table(box=box.SIMPLE_HEAVY, title="Scoreboard", header_style="bold")
    t.add_column("Rank",    width=6,  style="dim")
    t.add_column("Player",  width=20)
    t.add_column("Score",   width=8,  style="yellow bold")
    t.add_column("Solved",  width=8)
    t.add_column("Scenarios", style="dim")

    medals = {1: "🥇", 2: "🥈", 3: "🥉"}
    for i, entry in enumerate(board, 1):
        rank = medals.get(i, str(i))
        t.add_row(
            rank,
            entry["player"],
            str(entry["score"]),
            str(len(entry["solves"])),
            " ".join(entry["solves"]),
        )

    console.print(t)
    console.print()


if __name__ == "__main__":
    cli()
