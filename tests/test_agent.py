import pytest
import json
from fastapi.testclient import TestClient
from app.main import app
from app.digest import compute_arguments_digest

client = TestClient(app)

SAMPLE_INCIDENT = {
    "profile": "ga5-incident-agent/v2",
    "runId": "run-test-alpha-001",
    "agentName": "incident-response",
    "publicMarker": "audit-marker-123",
    "sensitive": {"accessToken": "SUPER_SECRET_TOKEN", "privateNote": "top-secret"},
    "incident": {
        "incidentId": "inc_999",
        "title": "Database Connection Pool Exhaustion",
        "service": "billing-api",
        "severity": "SEV-1",
        "transcript": "[ev_conn_spike] Connection pool exceeded 100% capacity\n[ev_db_slow] Latency spiked to 5000ms\n[ev_cpu_idle] CPU idle at 98%",
        "allowedRootCauses": ["connection_pool_exhaustion", "cpu_throttling", "disk_full"]
    },
    "toolCatalog": [
        {"name": "query_metrics", "description": "Fetch metrics", "inputSchema": {"service": "string"}},
        {"name": "check_db_pool", "description": "Inspect pool", "inputSchema": {"service": "string"}},
        {"name": "scale_service", "description": "Scale replicas", "inputSchema": {"service": "string"}},
        {"name": "rollback_deployment", "description": "Rollback", "inputSchema": {"service": "string"}}
    ],
    "policy": {
        "maximumDiagnostics": 3,
        "effectTools": ["scale_service", "rollback_deployment"],
        "approvalRequiredFor": ["rollback_deployment"],
        "doNotExport": ["accessToken"]
    }
}

def test_incident_start_and_dispatches():
    res = client.post("/v2/incidents", json=SAMPLE_INCIDENT)
    assert res.status_code == 200
    data = res.json()
    assert data["runId"] == "run-test-alpha-001"
    assert data["status"] == "waiting"
    assert data["diagnosis"]["rootCause"] in SAMPLE_INCIDENT["incident"]["allowedRootCauses"]
    assert len(data["diagnosis"]["evidence"]) >= 2
    assert len(data["dispatches"]) >= 1

    disp = data["dispatches"][0]
    assert disp["phase"] == "diagnostic"
    assert disp["attempt"] == 1
    assert "00-" in disp["traceparent"]

def test_replay_idempotency():
    res1 = client.post("/v2/incidents", json=SAMPLE_INCIDENT)
    res2 = client.post("/v2/incidents", json=SAMPLE_INCIDENT)
    assert res1.status_code == 200
    assert res2.status_code == 200
    assert res1.json() == res2.json()

def test_conflict_detection():
    altered = dict(SAMPLE_INCIDENT)
    altered["publicMarker"] = "different-marker"
    res = client.post("/v2/incidents", json=altered)
    assert res.status_code == 409

def test_invalid_profile():
    bad = dict(SAMPLE_INCIDENT)
    bad["runId"] = "run-bad-profile"
    bad["profile"] = "unsupported-profile"
    res = client.post("/v2/incidents", json=bad)
    assert res.status_code == 422

def test_503_retry_workflow():
    run_payload = dict(SAMPLE_INCIDENT)
    run_payload["runId"] = "run-503-test"
    init_res = client.post("/v2/incidents", json=run_payload)
    assert init_res.status_code == 200
    init_data = init_res.json()
    action = init_data["dispatches"][0]

    # Post 503 outcome
    rec_body = {
        "receiptId": "rec_503_1",
        "outcomes": [{
            "actionId": action["actionId"],
            "callId": action["callId"],
            "attempt": 1,
            "status": 503,
            "resultClass": "service_unavailable",
            "nonce": "nonce_503"
        }]
    }
    rec_res = client.post("/v2/incidents/run-503-test/receipts", json=rec_body)
    assert rec_res.status_code == 200
    rec_data = rec_res.json()
    assert rec_data["status"] == "waiting"
    assert len(rec_data["dispatches"]) == 1
    retry_disp = rec_data["dispatches"][0]
    assert retry_disp["attempt"] == 2
    assert retry_disp["actionId"] == action["actionId"]

def test_approval_gate_and_otlp_completion():
    run_payload = dict(SAMPLE_INCIDENT)
    run_payload["runId"] = "run-approval-flow"
    run_payload["incident"]["transcript"] = "[ev_1] bad deployment canary\n[ev_2] regression in canary"
    run_payload["policy"]["effectTools"] = ["rollback_deployment"]
    run_payload["policy"]["approvalRequiredFor"] = ["rollback_deployment"]

    # 1. Start incident
    init_res = client.post("/v2/incidents", json=run_payload)
    init_data = init_res.json()
    dispatches = init_data["dispatches"]

    # 2. Confirm diagnostics
    rec1 = {
        "receiptId": "rec_diag_ok",
        "outcomes": [
            {
                "actionId": d["actionId"],
                "callId": d["callId"],
                "attempt": 1,
                "status": 200,
                "resultClass": "diagnosis_confirmed",
                "nonce": f"nonce_{idx}"
            }
            for idx, d in enumerate(dispatches)
        ]
    }
    rec_res1 = client.post("/v2/incidents/run-approval-flow/receipts", json=rec1)
    rec_data1 = rec_res1.json()

    # Must require approval!
    assert rec_data1["status"] == "waiting"
    assert len(rec_data1["approvals"]) == 1
    app_req = rec_data1["approvals"][0]
    assert app_req["toolName"] == "rollback_deployment"

    # Check digest correctness
    expected_digest = compute_arguments_digest({"service": "billing-api"})
    assert app_req["argumentsDigest"] == expected_digest

    # 3. Grader approves
    app_receipt = {
        "receiptId": "rec_app_01",
        "approvals": [{
            "approvalId": app_req["approvalId"],
            "decision": "approved",
            "nonce": "grant_nonce_123"
        }]
    }
    rec_res2 = client.post("/v2/incidents/run-approval-flow/receipts", json=app_receipt)
    rec_data2 = rec_res2.json()
    assert rec_data2["status"] == "waiting"
    assert len(rec_data2["dispatches"]) == 1
    eff_disp = rec_data2["dispatches"][0]
    assert eff_disp["toolName"] == "rollback_deployment"
    assert eff_disp["approvalId"] == app_req["approvalId"]
    assert eff_disp["approvalNonce"] == "grant_nonce_123"

    # 4. Effect outcome
    eff_outcome = {
        "receiptId": "rec_eff_ok",
        "outcomes": [{
            "actionId": eff_disp["actionId"],
            "callId": eff_disp["callId"],
            "attempt": 1,
            "status": 200,
            "resultClass": "rollback_completed",
            "nonce": "eff_nonce_99"
        }]
    }
    final_res = client.post("/v2/incidents/run-approval-flow/receipts", json=eff_outcome)
    assert final_res.status_code == 200
    final_data = final_res.json()

    assert final_data["status"] == "completed"
    assert final_data["chosenEffect"] == "rollback_deployment"
    assert len(final_data["actionLog"]) > 0
    assert len(final_data["receiptLog"]) > 0
    assert "otlp" in final_data

    # Verify no secret leakage in OTLP
    otlp_str = json.dumps(final_data["otlp"])
    assert "SUPER_SECRET_TOKEN" not in otlp_str
    assert "top-secret" not in otlp_str
