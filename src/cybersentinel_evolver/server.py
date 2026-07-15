# FastAPI REST API + frontend server for CyberSentinel Evolver
from __future__ import annotations

import asyncio
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

from .attacks import AttackGenerator, MutationEngine
from .database import Database
from .detection import (
    BehavioralBaselineDetector,
    RandomDetector,
    RuleBasedDetector,
    run_tournament,
)
from .gap_analyzer import GapAnalyzer
from .metrics import record_all
from .self_promoter import SelfPromoter

DB_PATH = Path(
    os.environ.get("EVOLVER_DB", "~/cybersentinel-evolver/data.db")
).expanduser()
FRONTEND_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"

db = Database(DB_PATH)
app = FastAPI(title="CyberSentinel Evolver", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request Models ──────────────────────────────────────────────────────

class SelfPromptRequest(BaseModel):
    trigger: str = "mutation_escaped"
    context: str = "{}"


class GapAnalysisRequest(BaseModel):
    type: str = "coverage"


# ── Health ─────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "healthy", "version": "0.2.0"}


@app.get("/metrics")
async def prometheus_metrics():
    record_all(db)
    return PlainTextResponse(
        content=generate_latest().decode("utf-8"),
        media_type="text/plain; version=0.0.4",
    )


# ── Scenarios ──────────────────────────────────────────────────────────

@app.get("/api/scenarios")
async def list_scenarios():
    return db.get_scenarios()


@app.post("/api/scenarios/generate")
async def generate_scenarios():
    gen = AttackGenerator(db)
    scenarios = gen.generate()
    return {"status": "ok", "count": len(scenarios)}


# ── Tournaments ────────────────────────────────────────────────────────

@app.get("/api/tournaments")
async def list_tournaments():
    return db.get_tournament_results()


@app.post("/api/tournaments/run")
async def run_tournament_endpoint():
    scenarios_list = db.get_scenarios()
    if not scenarios_list:
        raise HTTPException(400, "No scenarios. Generate first.")

    from .models import Scenario
    scenario_objs = [Scenario.from_dict_row(s) for s in scenarios_list]
    detectors = [RuleBasedDetector(), BehavioralBaselineDetector(), RandomDetector()]
    results = await run_tournament(detectors, scenario_objs)
    for r in results:
        db.insert_tournament_result(r.to_dict())
    return {"status": "ok", "results": [r.to_dict() for r in results]}


# ── Gap Analysis ───────────────────────────────────────────────────────

@app.get("/api/gap-analysis")
async def list_gap_analysis(analysis_type: str | None = None):
    return db.get_gap_analysis(analysis_type=analysis_type)


@app.post("/api/gap-analysis/run")
async def run_gap_analysis(req: GapAnalysisRequest):
    analyzer = GapAnalyzer(db)
    if req.type == "mutations":
        findings = analyzer.analyze_mutations(escaped_only=True)
    elif req.type == "coverage":
        findings = analyzer.analyze_coverage()
    else:
        findings = []
    return {"status": "ok", "findings": [f.to_dict() for f in findings]}


# ── Self-Prompt ────────────────────────────────────────────────────────

@app.post("/api/self-prompt")
async def self_prompt(req: SelfPromptRequest):
    ctx = {}
    if req.context:
        import json
        ctx = json.loads(req.context)
    promoter = SelfPromoter(db=db)
    record, parsed = promoter.generate(req.trigger, ctx)
    return {"status": "ok", "record": record.to_dict(), "scenarios": parsed}


# ── Metrics ────────────────────────────────────────────────────────────

@app.get("/api/metrics")
async def metrics():
    scenarios = db.get_scenarios()
    tournaments = db.get_tournament_results()
    mutations = db.get_mutations()
    avg_wr = (
        sum(t["win_rate"] for t in tournaments) / len(tournaments)
        if tournaments
        else 0
    )
    abuse_types = len(set(s["abuse_type"] for s in scenarios))
    feeds = len(set(s["source_feed"] for s in scenarios))
    total_blocked = sum(t["cost_blocked"] for t in tournaments)
    total_missed = sum(t["cost_missed"] for t in tournaments)
    return {
        "total_scenarios": len(scenarios),
        "total_tournaments": len(tournaments),
        "total_mutations": len(mutations),
        "avg_win_rate": round(avg_wr, 4),
        "total_cost_blocked": round(total_blocked, 2),
        "total_cost_missed": round(total_missed, 2),
        "unique_abuse_types": abuse_types,
        "unique_feeds": feeds,
    }


# ── Evolution Loop ────────────────────────────────────────────────────

@app.post("/api/evolve")
async def evolve(weeks: int = 1, auto_promote: bool = False):
    gen = AttackGenerator(db)
    mut = MutationEngine(db)

    scenarios_list = db.get_scenarios()
    if not scenarios_list:
        gen.generate()
        scenarios_list = db.get_scenarios()

    from .models import Scenario
    scenario_objs = [Scenario.from_dict_row(s) for s in scenarios_list]
    detectors = [RuleBasedDetector(), BehavioralBaselineDetector()]
    results = await run_tournament(detectors, scenario_objs)

    for week in range(weeks):
        mutations = []
        for s in scenario_objs:
            if any(
                r.win_rate >= 1.0 and r.detector_id == detectors[0].detector_id
                for r in results
            ):
                children = mut.mutate(s, "identity_swap", n=3)
                mutations.extend(children)
        if mutations:
            scenario_objs.extend(mutations)
            results = await run_tournament(detectors, scenario_objs)
            for r in results:
                db.insert_tournament_result(r.to_dict())

    winner = None
    if auto_promote and results:
        winner = max(results, key=lambda r: r.win_rate).detector_id

    return {"status": "ok", "winner": winner}


# ── Static Frontend ───────────────────────────────────────────────────
# ── Static Frontend ───────────────────────────────────────────────────
frontend_assets = FRONTEND_DIST / "assets"
if frontend_assets.exists():
    app.mount("/assets", StaticFiles(directory=str(frontend_assets)), name="assets")

FRONTEND_INDEX = FRONTEND_DIST / "index.html"

@app.get("/", include_in_schema=False)
async def root():
    return FileResponse(FRONTEND_INDEX)

# SPA fallback: serve index.html for non-API GET requests
@app.get("/{full_path:path}", include_in_schema=False)
async def spa_fallback(full_path: str):
    # If it's an API or asset path that somehow missed, try file first
    if full_path.startswith("api/"):
        raise HTTPException(404)
    candidate = FRONTEND_DIST / full_path
    if candidate.is_file():
        return FileResponse(candidate)
    return FileResponse(FRONTEND_INDEX)


# ── Request Models ──────────────────────────────────────────────────────
