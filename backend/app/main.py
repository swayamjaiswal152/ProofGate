"""KAVACH / ProofGate API.

Day-1 skinny pipe: scan -> harden -> verify, plus a live proxy WebSocket.
The LLM-powered adversarial twin layers on top of these endpoints (Day 2).
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from .core.policy import policy_diff, recommend_policy
from .core.proxy import KavachProxy
from .core.runner import run_scenarios, verdict
from .core.scanner import scan
from .llm import client as llm_client
from .llm import twin as twin_mod
from .models import Policy

app = FastAPI(title="KAVACH / ProofGate", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

EXAMPLES = Path(__file__).parent.parent / "examples"


class ConfigBody(BaseModel):
    config: str


class HardenBody(BaseModel):
    config: str
    task_hint: str = ""


class SimulateBody(BaseModel):
    config: str
    policy: Policy | None = None  # omit to run against the raw (unprotected) agent


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "service": "kavach"}


@app.get("/api/example")
def example() -> dict:
    text = (EXAMPLES / "support_agent.yaml").read_text()
    return {"config": text}


@app.post("/api/scan")
def scan_endpoint(body: ConfigBody) -> dict:
    result = scan(body.config)
    return result.model_dump()


@app.post("/api/harden")
def harden_endpoint(body: HardenBody) -> dict:
    result = scan(body.config)
    policy = recommend_policy(result.agent, body.task_hint)
    return {
        "policy": policy.model_dump(),
        "diff": policy_diff(result.agent, policy),
    }


@app.post("/api/simulate")
def simulate_endpoint(body: SimulateBody) -> dict:
    result = scan(body.config)
    results = run_scenarios(result.agent, body.policy)
    return {
        "verdict": verdict(results),
        "scenarios": [
            {
                "id": r.scenario.id,
                "kind": r.scenario.kind,
                "title": r.scenario.title,
                "prompt": r.scenario.prompt,
                "success": r.success,
                "detail": r.detail,
                "events": [e.model_dump() for e in r.events],
            }
            for r in results
        ],
    }


@app.get("/api/llm-status")
def llm_status() -> dict:
    return {"available": llm_client.available(), "model": llm_client.MODEL}


@app.post("/api/twin")
def twin_endpoint(body: ConfigBody) -> dict:
    """Generate the adversarial twin (attacks + legit tasks) and prove before/after.

    Uses Claude when a key is present, otherwise a deterministic fallback.
    """
    result = scan(body.config)
    policy = recommend_policy(result.agent)

    scenarios = twin_mod.generate(result.agent)
    before = twin_mod.evaluate(scenarios, None)
    after = twin_mod.evaluate(scenarios, policy)

    return {
        "source": scenarios["source"],
        "attacks": scenarios["attacks"],
        "legit": scenarios["legit"],
        "risks": scenarios.get("risks", []),
        "before": before,
        "after": after,
        "risk_before": result.risk_score,
        "risk_after": _residual_risk(after),
        "policy": policy.model_dump(),
        "diff": policy_diff(result.agent, policy),
    }


class ReportBody(BaseModel):
    config: str
    twin: dict | None = None  # pass the /api/twin result to skip re-running Claude


@app.post("/api/report", response_class=HTMLResponse)
def report_endpoint(body: ReportBody) -> HTMLResponse:
    """Render the Evidence Ledger as a print-ready HTML audit report."""
    from .core.report import assemble_evidence, build_report_html

    if body.twin:
        agent = scan(body.config).agent  # fast deterministic re-scan for tool list
        t = body.twin
        evidence = {
            "agent": agent.model_dump(),
            "attacks": t.get("attacks", []),
            "legit": t.get("legit", []),
            "before": t["before"],
            "after": t["after"],
            "policy": t.get("policy", {}),
            "risk_before": t.get("risk_before", 0),
            "risk_after": t.get("risk_after", 0),
            "source": t.get("source", "fallback"),
        }
    else:
        evidence = assemble_evidence(body.config)

    return HTMLResponse(content=build_report_html(evidence))


@app.post("/api/verify")
def verify_endpoint(body: ConfigBody) -> dict:
    """Before/after in one call: raw agent vs hardened agent."""
    result = scan(body.config)
    policy = recommend_policy(result.agent)

    before = verdict(run_scenarios(result.agent, None))
    after = verdict(run_scenarios(result.agent, policy))
    return {
        "risk_before": result.risk_score,
        "risk_after": _residual_risk(after),
        "before": before,
        "after": after,
        "policy": policy.model_dump(),
    }


def _residual_risk(after: dict) -> int:
    """Residual risk after hardening: driven by any attack still succeeding."""
    if after["attacks_total"] == 0:
        return 5
    leaked = after["attacks_total"] - after["attacks_blocked"]
    return int(round(100 * leaked / after["attacks_total"])) if leaked else 9


# ---- Live proxy WebSocket -------------------------------------------------

@app.websocket("/ws/proxy")
async def proxy_ws(ws: WebSocket) -> None:
    """Client sends {config, policy?, tool, args}; we stream the decision back.

    For the live demo the client can fire tool calls one at a time and watch
    the ALLOW/BLOCK verdict arrive in real time.
    """
    await ws.accept()
    proxy = KavachProxy()
    loop = asyncio.get_event_loop()

    def on_event(ev):
        asyncio.run_coroutine_threadsafe(ws.send_json(ev.model_dump()), loop)

    proxy.subscribe(on_event)
    try:
        while True:
            msg = await ws.receive_json()
            if "policy" in msg and msg["policy"]:
                proxy.set_policy(Policy.model_validate(msg["policy"]))
            tool = msg.get("tool")
            if tool:
                proxy.evaluate(tool, msg.get("args", {}))
    except WebSocketDisconnect:
        return
