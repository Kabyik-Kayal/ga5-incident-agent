import os
import json
import logging
from typing import Any, Dict
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

from app.state import store
from app.planner import plan_incident

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("incident-agent")

app = FastAPI(
    title="Observable Incident Triage Agent",
    description="ga5-incident-agent/v2 compliant triage and telemetry service",
    version="2.0.0"
)

@app.get("/")
@app.get("/health")
async def health_check():
    gemini_configured = bool(os.getenv("GEMINI_API_KEY"))
    openai_configured = bool(os.getenv("OPENAI_API_KEY"))
    groq_configured = bool(os.getenv("GROQ_API_KEY"))

    active_provider = "gemini" if gemini_configured else ("openai" if openai_configured else ("groq" if groq_configured else "heuristic-fallback"))

    return {
        "status": "ok",
        "service": "ga5-incident-agent",
        "version": "2.0.0",
        "ai": {
            "provider": active_provider,
            "gemini_configured": gemini_configured,
            "openai_configured": openai_configured,
            "model": os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
        }
    }

@app.post("/debug/test-planner")
async def debug_test_planner(request: Request):
    import time
    body = await request.json()
    incident_info = body.get("incident", {})
    policy = body.get("policy", {})
    tool_catalog = body.get("toolCatalog", [])
    t0 = time.time()
    plan = await plan_incident(
        service=incident_info.get("service", "core-api"),
        title=incident_info.get("title", "Incident Outage"),
        transcript=incident_info.get("transcript", ""),
        allowed_causes=incident_info.get("allowedRootCauses", []),
        tool_catalog=tool_catalog,
        effect_tools=policy.get("effectTools", [])
    )
    elapsed = round(time.time() - t0, 3)
    return {"elapsed_seconds": elapsed, "plan": plan}

@app.post("/v2/incidents")
async def handle_incident(request: Request):
    raw_body = await request.body()
    try:
        body: Dict[str, Any] = json.loads(raw_body.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # Profile validation
    if body.get("profile") != "ga5-incident-agent/v2":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Unsupported profile"
        )

    run_id = body.get("runId")
    if not run_id:
        raise HTTPException(status_code=400, detail="Missing required field: runId")

    # Traceparent and tracestate extraction from headers
    incoming_traceparent = request.headers.get("traceparent")
    incoming_tracestate = request.headers.get("tracestate")

    # If run already exists, create_run handles replay or 409 conflict
    if store.get_run(run_id):
        resp, code = store.create_run(raw_body, body, incoming_traceparent, incoming_tracestate, {})
        headers = {}
        if incoming_tracestate:
            headers["tracestate"] = incoming_tracestate
        return JSONResponse(status_code=code, content=resp, headers=headers)

    # Sanitize: Strip sensitive data before planning
    incident_info = body.get("incident", {})
    policy = body.get("policy", {})
    tool_catalog = body.get("toolCatalog", [])

    plan = await plan_incident(
        service=incident_info.get("service", "core-api"),
        title=incident_info.get("title", "Incident Outage"),
        transcript=incident_info.get("transcript", ""),
        allowed_causes=incident_info.get("allowedRootCauses", []),
        tool_catalog=tool_catalog,
        effect_tools=policy.get("effectTools", [])
    )

    resp, code = store.create_run(raw_body, body, incoming_traceparent, incoming_tracestate, plan)
    headers = {}
    if incoming_tracestate:
        headers["tracestate"] = incoming_tracestate
    return JSONResponse(status_code=code, content=resp, headers=headers)

@app.post("/v2/incidents/{runId}/receipts")
async def handle_receipts(runId: str, request: Request):
    raw_body = await request.body()
    try:
        body: Dict[str, Any] = json.loads(raw_body.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    if not body.get("receiptId"):
        raise HTTPException(status_code=400, detail="Missing receiptId")

    resp = store.handle_receipt(runId, raw_body, body)
    
    headers = {}
    run = store.get_run(runId)
    if run and run.get("tracestate"):
        headers["tracestate"] = run["tracestate"]

    return JSONResponse(status_code=200, content=resp, headers=headers)

@app.get("/v2/incidents/{runId}")
async def get_incident(runId: str):
    run = store.get_run(runId)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    
    headers = {}
    if run.get("tracestate"):
        headers["tracestate"] = run["tracestate"]

    return JSONResponse(status_code=200, content=run["currentState"], headers=headers)
