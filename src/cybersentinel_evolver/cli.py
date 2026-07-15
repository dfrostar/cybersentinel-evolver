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
from .gap_analyzer import GapAnalyzer
from .models import now_ms
from .self_promoter import SelfPromoter

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

    detectors = [RuleBasedDetector(), BehavioralBaselineDetector()]
    results = asyncio.run(run_tournament(detectors, scenario_objs))

    console.print("[bold cyan]=== Evolution Loop ===[/bold cyan]")
    console.print(f"Starting with {len(scenario_objs)} scenarios")

    for week in range(weeks):
        console.print(f"\n[bold]Week {week + 1}[/bold]")

        mutations = []
        for s in scenario_objs:
            if any(r.win_rate >= 1.0 and r.detector_id == detectors[0].detector_id for r in results):
                children = mut.mutate(s, "identity_swap", n=3)
                mutations.extend(children)

        if mutations:
            console.print(f"Generated {len(mutations)} mutations")
            scenario_objs.extend(mutations)

            results = asyncio.run(run_tournament(detectors, scenario_objs))

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


# ── Self-Prompting Commands (v2.0) ───────────────────────────────────────


@cli.command("self-prompt")
@click.option(
    "--trigger",
    type=click.Choice(["mutation_escaped", "coverage_cliff", "tournament_tie", "feed_update"]),
    required=True,
    help="Trigger type for self-prompt",
)
@click.option(
    "--context",
    default="{}",
    help="JSON context for the prompt template",
)
@click.option(
    "--llm/--no-llm",
    default=False,
    help="Enable LLM call (requires API key). Default: template-only (no external calls).",
)
@click.pass_context
def self_prompt(ctx, trigger, context, llm):
    """Generate a self-prompt from gap analysis and optionally call LLM."""
    db = ctx.obj["db"]
    ctx_obj = json.loads(context) if isinstance(context, str) else context
    llm_client = None
    if llm:
        try:
            from .llm_client import get_llm_client

            llm_client = get_llm_client()
        except Exception as e:
            console.print(f"[yellow]LLM not available: {e}[/yellow]")
            console.print("[yellow]Falling back to template-only mode[/yellow]")

    promoter = SelfPromoter(db=db, llm_client=llm_client)
    record, parsed = promoter.generate(trigger, ctx_obj)

    console.print(f"[green]Prompt generated:[/green] {record.id}")
    console.print(f"[dim]{record.prompt_text[:200]}...[/dim]")
    console.print(f"Scenarios extracted: {len(parsed)}")
    if record.llm_response:
        console.print(f"LLM response: {record.llm_response[:200]}...")


@cli.command("gap-analysis")
@click.option(
    "--type",
    "analysis_type",
    type=click.Choice(["coverage", "drift", "cost_accuracy", "mutations"]),
    default="coverage",
    help="Gap analysis type",
)
@click.pass_context
def gap_analysis(ctx, analysis_type):
    """Run gap analysis and persist findings."""
    db = ctx.obj["db"]
    analyzer = GapAnalyzer(db)
    if analysis_type == "mutations":
        findings = analyzer.analyze_mutations(escaped_only=True)
    elif analysis_type == "coverage":
        findings = analyzer.analyze_coverage()
    else:
        findings = []

    if not findings:
        console.print("[green]No gaps detected.[/green]")
        return

    table = Table(title="Gap Analysis Findings")
    table.add_column("Type", style="cyan")
    table.add_column("Severity", style="magenta")
    table.add_column("Finding", style="bold")
    table.add_column("Recommended Prompt", style="blue")
    for f in findings:
        table.add_row(
            f.analysis_type,
            f"{f.severity:.2f}",
            str(f.finding)[:60],
            f.recommended_prompt,
        )
    console.print(table)


@cli.command("prompts")
@click.option("--trigger-type", default=None, help="Filter by trigger type")
@click.pass_context
def prompts(ctx, trigger_type):
    """Show self-prompt history."""
    db = ctx.obj["db"]
    prompts = db.get_prompts(trigger_type=trigger_type)

    if not prompts:
        console.print("[yellow]No prompts found.[/yellow]")
        return

    table = Table(title="Self-Prompt History")
    table.add_column("ID", style="dim")
    table.add_column("Trigger", style="cyan")
    table.add_column("Scenarios", style="magenta")
    table.add_column("Accepted", style="bold")
    table.add_column("Prompt", style="blue")

    for p in prompts:
        table.add_row(
            p["id"][:8],
            p["trigger_type"],
            str(p["scenarios_extracted"]),
            str(bool(p["accepted"])) if p["accepted"] is not None else "?",
            p["prompt_text"][:80] + "...",
        )
    console.print(table)


# ── CyberSentinel Integration (v2.0) ────────────────────────────────────


@cli.command("cs-integration")
@click.option("--host", default="http://localhost:3000", help="CyberSentinel API URL")
@click.option("--client-id", default="evolver-test", help="Client ID for JWT auth")
@click.option("--max-requests", default=None, type=int, help="Max requests to send")
@click.pass_context
def cs_integration(ctx, host, client_id, max_requests):
    """Run scenario requests against CyberSentinel and detect 5xx regressions."""
    from .cybersentinel_client import CyberSentinelClient

    db = ctx.obj["db"]
    client = CyberSentinelClient(host, client_id)

    console.print(f"[bold]CyberSentinel Integration Test[/bold]")
    console.print(f"Target: {host}")

    # Health check
    if client.health():
        console.print("[green]✓ Health check passed[/green]")
    else:
        console.print("[red]✗ Health check failed[/red]")
        return

    # Authenticate
    if client.authenticate():
        console.print("[green]✓ Authenticated[/green]")
    else:
        console.print("[red]✗ Auth failed[/red]")
        return

    # Load scenarios
    scenarios = db.get_scenarios()
    console.print(f"Loaded {len(scenarios)} scenarios from DB")

    # Run regression scan
    report = client.scan_scenario_requests(scenarios, max_requests=max_requests)

    # Print results
    console.print()
    console.print(report.summary())

    if report.has_regressions():
        console.print("\n[red bold]⚠ REGRESSIONS DETECTED[/red bold]")
        table = Table(title="5xx Regressions")
        table.add_column("Scenario", style="cyan")
        table.add_column("Method", style="magenta")
        table.add_column("Path", style="bold")
        table.add_column("Status", style="red")
        for r in report.results:
            if r.is_regression():
                table.add_row(r.scenario_name, r.method, r.path, str(r.status_code))
        console.print(table)


def main():
    cli()


if __name__ == "__main__":
    main()
