from __future__ import annotations

import asyncio
import json
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from .attacks import AttackGenerator, MutationEngine
from .database import Database
from .detection import (
    BehavioralBaselineDetector,
    RandomDetector,
    RuleBasedDetector,
    run_mutation_tournament,
    run_tournament,
)
from .models import now_ms

console = Console()


@click.group()
@click.option("--db", default="~/cybersentinel-evolver/data.db", help="SQLite database path")
@click.pass_context
def cli(ctx, db):
    """CyberSentinel Evolver — self-improving abuse detection testing platform."""
    ctx.ensure_object(dict)
    ctx.obj["db"] = Database(Path(db).expanduser())


@cli.command()
@click.option("--feed", default="all", help="Threat feed to generate from")
@click.pass_context
def scenarios(ctx, feed):
    """Generate attack scenarios from threat intelligence feeds."""
    db = ctx.obj["db"]
    gen = AttackGenerator(db)
    scenarios = gen.generate()
    console.print(f"[green]Generated {len(scenarios)} scenarios[/green]")
    for s in scenarios:
        console.print(f"  - {s.name} ({s.abuse_type}) from {s.source_feed}")


@cli.command()
@click.option("--detectors", default="rule_based,behavioral,random", help="Comma-separated detector IDs")
@click.option("--scenarios", default="all", help="Scenario filter (all or count)")
@click.pass_context
def tournament(ctx, detectors, scenarios):
    """Run a tournament between detectors on current scenarios."""
    db = ctx.obj["db"]
    scenarios_list = db.get_scenarios()

    if not scenarios_list:
        console.print("[red]No scenarios found. Run 'scenarios generate' first.[/red]")
        return

    from .models import Scenario
    scenario_objs = [Scenario.from_dict_row(s) for s in scenarios_list]

    if scenarios != "all":
        try:
            n = int(scenarios)
            scenario_objs = scenario_objs[:n]
        except ValueError:
            pass

    detector_map = {
        "rule_based": RuleBasedDetector(),
        "behavioral": BehavioralBaselineDetector(),
        "random": RandomDetector(true_positive_rate=0.5),
    }

    selected = []
    for d in detectors.split(","):
        d = d.strip()
        if d in detector_map:
            selected.append(detector_map[d])
        else:
            console.print(f"[yellow]Unknown detector: {d}[/yellow]")

    if not selected:
        console.print("[red]No valid detectors selected.[/red]")
        return

    console.print(f"Running tournament: {len(selected)} detectors × {len(scenario_objs)} scenarios")
    results = asyncio.run(run_tournament(selected, scenario_objs))

    table = Table(title="Tournament Results")
    table.add_column("Detector", style="cyan")
    table.add_column("Scenarios", style="magenta")
    table.add_column("Detected", style="green")
    table.add_column("Win Rate", style="bold")
    table.add_column("CI", style="blue")
    table.add_column("Cost Blocked", style="green")
    table.add_column("Cost Missed", style="red")

    for r in results:
        table.add_row(
            r.detector_id,
            str(r.scenario_count),
            str(r.detected_count),
            f"{r.win_rate:.2%}",
            f"[{r.confidence_low:.2%}, {r.confidence_high:.2%}]",
            f"${r.cost_blocked:,.2f}",
            f"${r.cost_missed:,.2f}",
        )
        db.insert_tournament_result(r.to_dict())

    console.print(table)


@cli.command()
@click.option("--weeks", default=1, help="Number of weeks to simulate")
@click.option("--auto-promote", is_flag=True, help="Automatically promote winning detector")
@click.pass_context
def evolve(ctx, weeks, auto_promote):
    """Run evolution loop: mutate survivors and run tournament."""
    db = ctx.obj["db"]
    gen = AttackGenerator(db)
    mut = MutationEngine(db)

    scenarios_list = db.get_scenarios()
    if not scenarios_list:
        console.print("[yellow]No scenarios found. Generating fresh scenarios...[/yellow]")
        gen.generate()
        scenarios_list = db.get_scenarios()

    from .models import Scenario
    scenario_objs = [Scenario.from_dict_row(s) for s in scenarios_list]

    # Run baseline tournament first
    detectors = [RuleBasedDetector(), BehavioralBaselineDetector()]
    results = asyncio.run(run_tournament(detectors, scenario_objs))

    console.print("[bold cyan]=== Evolution Loop ===[/bold cyan]")
    console.print(f"Starting with {len(scenario_objs)} scenarios")

    for week in range(weeks):
        console.print(f"\n[bold]Week {week + 1}[/bold]")

        # Mutate scenarios where detector had 100% win rate
        mutations = []
        for s in scenario_objs:
            if any(r.win_rate >= 1.0 and r.detector_id == detectors[0].detector_id for r in results):
                children = mut.mutate(s, "identity_swap", n=3)
                mutations.extend(children)

        if mutations:
            console.print(f"Generated {len(mutations)} mutations")
            scenario_objs.extend(mutations)

            results = asyncio.run(run_tournament(detectors, scenario_objs))

            # Report
            for r in results:
                console.print(f"  {r.detector_id}: win_rate={r.win_rate:.2%}, cost_blocked=${r.cost_blocked:,.2f}")
                db.insert_tournament_result(r.to_dict())
        else:
            console.print("  No mutations required (detectors not at 100%)")

    if auto_promote and results:
        winner = max(results, key=lambda r: r.win_rate)
        console.print(f"\n[green bold]Winner: {winner.detector_id} (win_rate={winner.win_rate:.2%})[/green bold]")


@cli.command()
@click.option("--format", "fmt", type=click.Choice(["json", "table"]), default="table")
@click.option("--since", default=None, help="Report since epoch ms")
@click.pass_context
def report(ctx, fmt, since):
    """Show cost-captured summary."""
    db = ctx.obj["db"]
    since_ms = int(since) if since else None
    results = db.get_tournament_results(since=since_ms)

    if not results:
        console.print("[yellow]No tournament results found.[/yellow]")
        return

    if fmt == "json":
        console.print(json.dumps(results, indent=2))
    else:
        table = Table(title="Tournament History")
        table.add_column("Run ID", style="dim")
        table.add_column("Detector", style="cyan")
        table.add_column("Scenarios", style="magenta")
        table.add_column("Win Rate", style="bold")
        table.add_column("Cost Blocked", style="green")
        table.add_column("Cost Missed", style="red")
        table.add_column("Run At", style="blue")

        for r in results:
            from datetime import datetime, timezone
            dt = datetime.fromtimestamp(r["ran_at"] / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
            table.add_row(
                r["run_id"][:8],
                r["detector_id"],
                str(r["scenario_count"]),
                f"{r['win_rate']:.2%}",
                f"${r['cost_blocked']:,.2f}",
                f"${r['cost_missed']:,.2f}",
                dt,
            )

        console.print(table)


@cli.command()
@click.argument("scenario_id")
@click.pass_context
def lineage(ctx, scenario_id):
    """Show mutation lineage for a scenario."""
    db = ctx.obj["db"]

    def show_scenario(sid: str, indent: int = 0):
        s = db.get_scenario(sid)
        if s:
            prefix = "  " * indent
            console.print(f"{prefix}- [{s['id'][:8]}] {s['name']} (gen={s['generation']}, depth={s['mutation_depth']})")

    show_scenario(scenario_id)


def main():
    cli()


if __name__ == "__main__":
    main()
