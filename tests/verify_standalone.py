import sys
import os
import copy
sys.path.insert(0, os.path.abspath("."))
import asyncio
import json
from app.state import store
from app.planner import plan_incident
from app.digest import compute_arguments_digest

SAMPLE_PAYLOAD = {
    "profile": "ga5-incident-agent/v2",
    "runId": "verify-run-001",
    "agentName": "incident-response",
    "publicMarker": "audit-test-marker",
    "sensitive": {"accessToken": "LEAK_SECRET_123"},
    "incident": {
        "incidentId": "inc_1",
        "title": "Database Connection Pool Exhaustion",
        "service": "billing-service",
        "severity": "SEV-1",
        "transcript": "[ev_pool_99] active pool connections 100/100 exhausted\n[ev_lat_500] query latency 5000ms\n[ev_cpu_low] cpu idle 95%",
        "allowedRootCauses": ["connection_pool_exhaustion", "cpu_spike"]
    },
    "toolCatalog": [
        {"name": "check_pool_status", "description": "Check db pool", "inputSchema": {"properties": {"service": {"type": "string"}}}},
        {"name": "query_metrics", "description": "Query metrics", "inputSchema": {"properties": {"metric": {"type": "string"}}}},
        {"name": "scale_service", "description": "Scale instances", "inputSchema": {"properties": {"service": {"type": "string"}}}},
        {"name": "rollback_deployment", "description": "Rollback", "inputSchema": {"properties": {"service": {"type": "string"}}}},
        {"name": "page_owner", "description": "Page owner", "inputSchema": {"properties": {"service": {"type": "string"}}}}
    ],
    "policy": {
        "maximumDiagnostics": 3,
        "effectTools": ["scale_service", "rollback_deployment", "page_owner"],
        "approvalRequiredFor": ["rollback_deployment"],
        "doNotExport": ["accessToken"]
    }
}

async def main():
    print("--- TEST SUITE: Observable Incident Triage Agent ---")
    
    # TEST 1: Normal Diagnostic, 503 Retry, and Safe Effect
    print("\n1. Testing Planner & Basic Flow...")
    plan = await plan_incident(
        service="billing-service",
        title=SAMPLE_PAYLOAD["incident"]["title"],
        transcript=SAMPLE_PAYLOAD["incident"]["transcript"],
        allowed_causes=SAMPLE_PAYLOAD["incident"]["allowedRootCauses"],
        tool_catalog=SAMPLE_PAYLOAD["toolCatalog"],
        effect_tools=SAMPLE_PAYLOAD["policy"]["effectTools"]
    )
    assert plan["rootCause"] == "connection_pool_exhaustion"
    assert len(plan["evidence"]) >= 2
    assert len(plan["diagnostics"]) >= 1
    print(f"   Root Cause: {plan['rootCause']}, Evidence: {plan['evidence']}")

    raw_body = json.dumps(SAMPLE_PAYLOAD).encode("utf-8")
    resp, code = store.create_run(raw_body, SAMPLE_PAYLOAD, None, None, plan)
    assert code == 200
    assert resp["status"] == "waiting"
    disp1 = resp["dispatches"][0]
    print(f"   Dispatched: {disp1['toolName']} (attempt: {disp1['attempt']})")

    # Replay idempotency test
    replay_resp, replay_code = store.create_run(raw_body, SAMPLE_PAYLOAD, None, None, {})
    assert replay_code == 200
    assert replay_resp == resp
    print("   Replay idempotency: PASSED")

    # Conflict test
    altered_body = dict(SAMPLE_PAYLOAD)
    altered_body["publicMarker"] = "conflicting-marker"
    try:
        store.create_run(json.dumps(altered_body).encode("utf-8"), altered_body, None, None, {})
        assert False, "Should have raised 409 Conflict"
    except Exception as e:
        assert getattr(e, "status_code", None) == 409
        print("   Conflict detection (409): PASSED")

    # 503 Retry test
    rec_503 = {
        "receiptId": "rec_001",
        "outcomes": [{
            "actionId": disp1["actionId"],
            "callId": disp1["callId"],
            "attempt": 1,
            "status": 503,
            "resultClass": "retryable_failure",
            "nonce": "n_503"
        }]
    }
    resp_503 = store.handle_receipt("verify-run-001", json.dumps(rec_503).encode("utf-8"), rec_503)
    assert resp_503["status"] == "waiting"
    retry_disp = resp_503["dispatches"][0]
    assert retry_disp["attempt"] == 2
    print("   503 Retry attempt 2: PASSED")

    # Diagnostic 200 OK -> Effect dispatch
    rec_diag_ok = {
        "receiptId": "rec_002",
        "outcomes": [{
            "actionId": retry_disp["actionId"],
            "callId": retry_disp["callId"],
            "attempt": 2,
            "status": 200,
            "resultClass": "diagnosis_confirmed",
            "nonce": "n_ok"
        }]
    }
    resp_eff = store.handle_receipt("verify-run-001", json.dumps(rec_diag_ok).encode("utf-8"), rec_diag_ok)
    assert resp_eff["status"] == "waiting"
    eff_disp = resp_eff["dispatches"][0]
    assert eff_disp["phase"] == "effect"
    print(f"   Diagnostic succeeded -> Effect dispatched: {eff_disp['toolName']}")

    # Effect 200 OK -> Terminal completed state
    rec_eff_ok = {
        "receiptId": "rec_003",
        "outcomes": [{
            "actionId": eff_disp["actionId"],
            "callId": eff_disp["callId"],
            "attempt": 1,
            "status": 200,
            "resultClass": "scale_done",
            "nonce": "n_eff"
        }]
    }
    final_resp = store.handle_receipt("verify-run-001", json.dumps(rec_eff_ok).encode("utf-8"), rec_eff_ok)
    assert final_resp["status"] == "completed"
    assert "otlp" in final_resp
    otlp_str = json.dumps(final_resp["otlp"])
    assert "LEAK_SECRET_123" not in otlp_str
    print("   Completion & OTLP Telemetry with Zero Secrets: PASSED")

    # TEST 2: Approval Gate Flow
    print("\n2. Testing Approval Gate Flow (rollback_deployment)...")
    app_payload = copy.deepcopy(SAMPLE_PAYLOAD)
    app_payload["runId"] = "verify-run-approval"
    app_payload["incident"]["transcript"] = "[ev_101] canary deployment v2.1.0 regression spike\n[ev_102] 500 errors on canary"
    app_payload["incident"]["allowedRootCauses"] = ["canary_regression"]
    app_payload["policy"]["effectTools"] = ["rollback_deployment"]

    app_plan = await plan_incident(
        service="billing-service",
        title="Canary Regression",
        transcript=app_payload["incident"]["transcript"],
        allowed_causes=app_payload["incident"]["allowedRootCauses"],
        tool_catalog=app_payload["toolCatalog"],
        effect_tools=app_payload["policy"]["effectTools"]
    )
    resp_app_init, _ = store.create_run(json.dumps(app_payload).encode("utf-8"), app_payload, None, None, app_plan)
    diag_disp = resp_app_init["dispatches"][0]

    # Outcome for diagnostic
    rec_diag = {
        "receiptId": "rec_app_diag",
        "outcomes": [{
            "actionId": diag_disp["actionId"],
            "callId": diag_disp["callId"],
            "attempt": 1,
            "status": 200,
            "resultClass": "diagnosis_confirmed",
            "nonce": "n_diag"
        }]
    }
    resp_app_gate = store.handle_receipt("verify-run-approval", json.dumps(rec_diag).encode("utf-8"), rec_diag)
    assert resp_app_gate["status"] == "waiting"
    assert len(resp_app_gate["approvals"]) == 1
    app_item = resp_app_gate["approvals"][0]
    assert app_item["toolName"] == "rollback_deployment"
    print(f"   Approval Gate requested: tool={app_item['toolName']}, digest={app_item['argumentsDigest'][:16]}...")

    # Grader Approves
    app_grant = {
        "receiptId": "rec_app_grant",
        "approvals": [{
            "approvalId": app_item["approvalId"],
            "decision": "approved",
            "nonce": "grant_nonce_xyz"
        }]
    }
    resp_app_dispatched = store.handle_receipt("verify-run-approval", json.dumps(app_grant).encode("utf-8"), app_grant)
    assert resp_app_dispatched["status"] == "waiting"
    assert len(resp_app_dispatched["dispatches"]) == 1
    approved_disp = resp_app_dispatched["dispatches"][0]
    assert approved_disp["toolName"] == "rollback_deployment"
    assert approved_disp["approvalId"] == app_item["approvalId"]
    assert approved_disp["approvalNonce"] == "grant_nonce_xyz"
    print("   Approved dispatch emitted with matching approvalId and nonce: PASSED")

    # Effect outcome -> Completed
    rec_app_eff_ok = {
        "receiptId": "rec_app_eff_ok",
        "outcomes": [{
            "actionId": approved_disp["actionId"],
            "callId": approved_disp["callId"],
            "attempt": 1,
            "status": 200,
            "resultClass": "rollback_ok",
            "nonce": "n_app_eff"
        }]
    }
    final_app_resp = store.handle_receipt("verify-run-approval", json.dumps(rec_app_eff_ok).encode("utf-8"), rec_app_eff_ok)
    assert final_app_resp["status"] == "completed"
    assert final_app_resp["chosenEffect"] == "rollback_deployment"
    # Verify approval_gate span is in OTLP
    spans = final_app_resp["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
    assert any(s["name"] == "approval_gate" for s in spans)
    print("   Approval Gate span in OTLP: PASSED")

    # TEST 3: Scaling Limit Detection -> page_owner
    print("\n3. Testing Scaling Limit Detection (page_owner)...")
    limit_payload = copy.deepcopy(SAMPLE_PAYLOAD)
    limit_payload["runId"] = "verify-run-scaling-limit"
    limit_payload["incident"]["transcript"] = "[ev_99] service reached max replica scaling limit (cannot scale further)\n[ev_100] high traffic"
    limit_payload["incident"]["allowedRootCauses"] = ["high_traffic"]

    limit_plan = await plan_incident(
        service="billing-service",
        title="High Traffic At Scaling Limit",
        transcript=limit_payload["incident"]["transcript"],
        allowed_causes=limit_payload["incident"]["allowedRootCauses"],
        tool_catalog=limit_payload["toolCatalog"],
        effect_tools=limit_payload["policy"]["effectTools"]
    )
    resp_limit_init, _ = store.create_run(json.dumps(limit_payload).encode("utf-8"), limit_payload, None, None, limit_plan)
    limit_diag = resp_limit_init["dispatches"][0]

    rec_limit_diag = {
        "receiptId": "rec_lim_diag",
        "outcomes": [{
            "actionId": limit_diag["actionId"],
            "callId": limit_diag["callId"],
            "attempt": 1,
            "status": 200,
            "resultClass": "confirmed",
            "nonce": "n_lim"
        }]
    }
    resp_limit_eff = store.handle_receipt("verify-run-scaling-limit", json.dumps(rec_limit_diag).encode("utf-8"), rec_limit_diag)
    assert resp_limit_eff["status"] == "waiting"
    assert resp_limit_eff["dispatches"][0]["toolName"] == "page_owner"
    print("   Detected scaling limit -> correctly selected page_owner instead of scale_service: PASSED")

    # TEST 4: Timeout Diagnostic -> Effect Suppression
    print("\n4. Testing Timeout Diagnostic -> Effect Suppression...")
    timeout_payload = copy.deepcopy(SAMPLE_PAYLOAD)
    timeout_payload["runId"] = "verify-run-timeout"

    t_plan = await plan_incident(
        service="billing-service",
        title="Timeout Test",
        transcript=timeout_payload["incident"]["transcript"],
        allowed_causes=timeout_payload["incident"]["allowedRootCauses"],
        tool_catalog=timeout_payload["toolCatalog"],
        effect_tools=timeout_payload["policy"]["effectTools"]
    )
    resp_t_init, _ = store.create_run(json.dumps(timeout_payload).encode("utf-8"), timeout_payload, None, None, t_plan)
    t_diag = resp_t_init["dispatches"][0]

    rec_timeout = {
        "receiptId": "rec_t_out",
        "outcomes": [{
            "actionId": t_diag["actionId"],
            "callId": t_diag["callId"],
            "attempt": 1,
            "status": 0,
            "errorType": "timeout",
            "nonce": "n_timeout"
        }]
    }
    resp_t_final = store.handle_receipt("verify-run-timeout", json.dumps(rec_timeout).encode("utf-8"), rec_timeout)
    assert resp_t_final["status"] == "failed"
    assert len(resp_t_final["suppressed"]) > 0
    print(f"   Timeout suppressed effect {resp_t_final['suppressed']} and set status to failed: PASSED")

    print("\n========================================================")
    print("[SUCCESS] ALL 4 CORE LIFE-CYCLE AND AUDIT TESTS PASSED 100%!")
    print("========================================================")

if __name__ == "__main__":
    asyncio.run(main())
