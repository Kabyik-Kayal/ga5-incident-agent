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
    return {"status": "ok", "service": "ga5-incident-agent", "version": "2.0.0"}

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

    # Traceparent extraction from headers if present
    incoming_traceparent = request.headers.get("traceparent")

    # If run already exists, create_run handles replay or 409 conflict
    if store.get_run(run_id):
        resp, code = store.create_run(raw_body, body, incoming_traceparent, {})
        return JSONResponse(status_code=code, content=resp)

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

    resp, code = store.create_run(raw_body, body, incoming_traceparent, plan)
    return JSONResponse(status_code=code, content=resp)

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
    return JSONResponse(status_code=200, content=resp)

@app.get("/v2/incidents/{runId}")
async def get_incident(runId: str):
    run = store.get_run(runId)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return JSONResponse(status_code=200, content=run["currentState"])
