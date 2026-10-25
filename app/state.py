import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple
try:
    from fastapi import HTTPException
except ImportError:
    class HTTPException(Exception):
        def __init__(self, status_code: int, detail: str = ""):
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

from app.telemetry import (
    gen_trace_id,
    gen_span_id,
    format_traceparent,
    build_otlp_payload
)
from app.digest import compute_arguments_digest

class StateStore:
    def __init__(self):
        self.runs: Dict[str, Dict[str, Any]] = {}

    def get_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        return self.runs.get(run_id)

    def create_run(
        self,
        raw_body: bytes,
        body_dict: Dict[str, Any],
        incoming_traceparent: Optional[str],
        incoming_tracestate: Optional[str],
        plan: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], int]:
        run_id = body_dict["runId"]
        body_hash = hashlib.sha256(raw_body).hexdigest()

        # Replay / Conflict check
        if run_id in self.runs:
            existing = self.runs[run_id]
            if existing["bodyHash"] == body_hash:
                return existing["initialResponse"], 200
            else:
                raise HTTPException(
                    status_code=409,
                    detail="Conflict: runId exists with different payload"
                )

        # W3C Trace context
        trace_id = gen_trace_id()
        parent_span_id = ""
        if incoming_traceparent and incoming_traceparent.startswith("00-"):
            parts = incoming_traceparent.split("-")
            if len(parts) >= 3 and len(parts[1]) == 32:
                trace_id = parts[1]
                parent_span_id = parts[2]

        server_span_id = gen_span_id()
        agent_span_id = gen_span_id()
        chat_span_id = gen_span_id()

        policy = body_dict.get("policy", {})
        incident_info = body_dict.get("incident", {})
        public_marker = body_dict.get("publicMarker", "marker")

        logical_actions: Dict[str, Dict[str, Any]] = {}
        dispatches: List[Dict[str, Any]] = []

        # Create initial diagnostic dispatches
        for diag in plan.get("diagnostics", []):
            act_id = "act_" + gen_span_id()[:10]
            call_id = "call_" + gen_span_id()[:10]
            client_span_id = gen_span_id()
            exec_span_id = gen_span_id()

            tp = format_traceparent(trace_id, client_span_id)
            disp = {
                "actionId": act_id,
                "callId": call_id,
                "phase": "diagnostic",
                "toolName": diag["toolName"],
                "arguments": diag["arguments"],
                "evidence": diag["evidence"],
                "attempt": 1,
                "traceparent": tp
            }
            if incoming_tracestate:
                disp["tracestate"] = incoming_tracestate

            dispatches.append(disp)

            logical_actions[act_id] = {
                "actionId": act_id,
                "callId": call_id,
                "toolName": diag["toolName"],
                "phase": "diagnostic",
                "arguments": diag["arguments"],
                "evidence": diag["evidence"],
                "execSpanId": exec_span_id,
                "attempts": [{
                    "attempt": 1,
                    "clientSpanId": client_span_id
                }]
            }

        initial_response = {
            "runId": run_id,
            "status": "waiting",
            "diagnosis": {
                "rootCause": plan["rootCause"],
                "evidence": plan["evidence"]
            },
            "dispatches": dispatches,
            "approvals": []
        }

        self.runs[run_id] = {
            "runId": run_id,
            "bodyHash": body_hash,
            "traceId": trace_id,
            "tracestate": incoming_tracestate or "",
            "parentTraceSpanId": parent_span_id,
            "serverSpanId": server_span_id,
            "agentSpanId": agent_span_id,
            "chatSpanId": chat_span_id,
            "publicMarker": public_marker,
            "modelName": plan.get("modelName", "gemini-2.0-flash"),
            "diagnosis": initial_response["diagnosis"],
            "intendedEffect": plan.get("intendedEffect", {}),
            "policy": policy,
            "toolCatalog": body_dict.get("toolCatalog", []),
            "incident": incident_info,
            "logicalActions": logical_actions,
            "actionLog": list(dispatches),
            "receiptLog": [],
            "initialResponse": initial_response,
            "currentState": initial_response,
            "status": "waiting",
            "receiptResponses": {},
            "pendingApproval": None,
            "approvalUsed": None,
            "chosenEffect": None
        }

        return initial_response, 200

    def handle_receipt(
        self,
        run_id: str,
        raw_body: bytes,
        receipt_dict: Dict[str, Any]
    ) -> Dict[str, Any]:
        if run_id not in self.runs:
            raise HTTPException(status_code=404, detail="Unknown runId")

        run = self.runs[run_id]
        receipt_id = receipt_dict["receiptId"]
        body_hash = hashlib.sha256(raw_body).hexdigest()

        # Replay and Conflict Check
        if receipt_id in run["receiptResponses"]:
            saved = run["receiptResponses"][receipt_id]
            if saved["hash"] == body_hash:
                return saved["response"]
            else:
                raise HTTPException(
                    status_code=409,
                    detail="Conflict: receiptId payload changed"
                )

        trace_id = run["traceId"]
        tracestate = run.get("tracestate", "")

        # 1. Process Approvals Receipt
        if "approvals" in receipt_dict and receipt_dict["approvals"]:
            for app_rec in receipt_dict["approvals"]:
                app_id = app_rec["approvalId"]
                decision = app_rec.get("decision", "approved")
                nonce = app_rec.get("nonce", "")

                run["receiptLog"].append({
                    "receiptId": receipt_id,
                    "approvalId": app_id,
                    "decision": decision,
                    "nonce": nonce
                })

                pending = run.get("pendingApproval")
                if pending and pending["approvalId"] == app_id and decision == "approved":
                    run["approvalUsed"] = {"approvalId": app_id, "nonce": nonce}

                    act_id = pending["actionId"]
                    call_id = pending["callId"]
                    tool_name = pending["toolName"]
                    args = pending["arguments"]
                    client_span_id = gen_span_id()

                    effect_disp = {
                        "actionId": act_id,
                        "callId": call_id,
                        "phase": "effect",
                        "toolName": tool_name,
                        "arguments": args,
                        "approvalId": app_id,
                        "approvalNonce": nonce,
                        "attempt": 1,
                        "traceparent": format_traceparent(trace_id, client_span_id)
                    }
                    if tracestate:
                        effect_disp["tracestate"] = tracestate

                    run["actionLog"].append(effect_disp)
                    run["logicalActions"][act_id]["attempts"].append({
                        "attempt": 1,
                        "clientSpanId": client_span_id
                    })
                    run["pendingApproval"] = None

                    resp = {
                        "runId": run_id,
                        "status": "waiting",
                        "dispatches": [effect_disp],
                        "approvals": []
                    }
                    run["receiptResponses"][receipt_id] = {"hash": body_hash, "response": resp}
                    run["currentState"] = resp
                    return resp

        # 2. Process Outcomes Receipt
        if "outcomes" in receipt_dict and receipt_dict["outcomes"]:
            has_503_retry = False
            retry_dispatches: List[Dict[str, Any]] = []

            for outcome in receipt_dict["outcomes"]:
                act_id = outcome.get("actionId")
                call_id = outcome.get("callId")
                attempt_num = outcome.get("attempt", 1)
                stat = outcome.get("status", 200)
                nonce = outcome.get("nonce", "")
                err_type = outcome.get("errorType")
                res_class = outcome.get("resultClass", "ok")

                run["receiptLog"].append({
                    "receiptId": receipt_id,
                    "actionId": act_id,
                    "callId": call_id,
                    "attempt": attempt_num,
                    "status": stat,
                    "resultClass": res_class,
                    "nonce": nonce
                })

                if act_id and act_id in run["logicalActions"]:
                    act_meta = run["logicalActions"][act_id]
                    for att in act_meta["attempts"]:
                        if att["attempt"] == attempt_num:
                            att["receiptId"] = receipt_id
                            att["nonce"] = nonce
                            att["status"] = stat
                            att["errorType"] = err_type

                    # 503 Retry logic: allows exactly one retry
                    if stat == 503 and attempt_num == 1:
                        has_503_retry = True
                        new_client_span_id = gen_span_id()
                        retry_disp = {
                            "actionId": act_id,
                            "callId": call_id,
                            "phase": act_meta["phase"],
                            "toolName": act_meta["toolName"],
                            "arguments": act_meta["arguments"],
                            "attempt": 2,
                            "traceparent": format_traceparent(trace_id, new_client_span_id)
                        }
                        if act_meta.get("evidence"):
                            retry_disp["evidence"] = act_meta["evidence"]
                        if tracestate:
                            retry_disp["tracestate"] = tracestate

                        retry_dispatches.append(retry_disp)
                        run["actionLog"].append(retry_disp)
                        act_meta["attempts"].append({
                            "attempt": 2,
                            "clientSpanId": new_client_span_id
                        })

            # If retrying a 503, return immediately with the retry dispatch
            if has_503_retry:
                resp = {
                    "runId": run_id,
                    "status": "waiting",
                    "dispatches": retry_dispatches,
                    "approvals": []
                }
                run["receiptResponses"][receipt_id] = {"hash": body_hash, "response": resp}
                run["currentState"] = resp
                return resp

        # 3. Check State Transitions
        diag_actions = [m for m in run["logicalActions"].values() if m["phase"] == "diagnostic"]
        effect_actions = [m for m in run["logicalActions"].values() if m["phase"] == "effect"]

        # Has each diagnostic finished?
        def action_resolved(meta):
            for att in meta["attempts"]:
                if att.get("status") == 200 or att.get("errorType") == "timeout" or att.get("status") == 0:
                    return True
            return False

        all_diags_resolved = all(action_resolved(m) for m in diag_actions)

        # If any diagnostic is still in progress, stay in waiting
        if not all_diags_resolved:
            resp = {
                "runId": run_id,
                "status": "waiting",
                "dispatches": [],
                "approvals": []
            }
            run["receiptResponses"][receipt_id] = {"hash": body_hash, "response": resp}
            run["currentState"] = resp
            return resp

        # Did any diagnostic timeout?
        has_timeout = any(
            att.get("errorType") == "timeout" or att.get("status") == 0
            for meta in diag_actions
            for att in meta["attempts"]
        )

        if has_timeout:
            # "A status:0,errorType:'timeout' fails the diagnostic, so do not send its dependent effect."
            suppressed_effect = run["intendedEffect"].get("toolName", "scale_service") if run.get("intendedEffect") else "scale_service"
            final_resp = {
                "runId": run_id,
                "status": "failed",
                "diagnosis": run["diagnosis"],
                "chosenEffect": None,
                "suppressed": [suppressed_effect],
                "actionLog": run["actionLog"],
                "receiptLog": run["receiptLog"],
                "otlp": build_otlp_payload(run)
            }
            run["status"] = "failed"
            run["currentState"] = final_resp
            run["receiptResponses"][receipt_id] = {"hash": body_hash, "response": final_resp}
            return final_resp

        # All diagnostics succeeded! Check if effect has been dispatched yet
        if not effect_actions:
            # Plan or retrieve effect
            policy = run["policy"]
            effect_tools = policy.get("effectTools", ["scale_service"])
            approval_req = policy.get("approvalRequiredFor", [])
            
            planned_eff = run.get("intendedEffect", {})
            chosen_tool = planned_eff.get("toolName") or (effect_tools[0] if effect_tools else "scale_service")
            chosen_args = planned_eff.get("arguments") or {"service": run["incident"].get("service", "core-api")}

            # Scaling limit verification
            transcript_txt = run["incident"].get("transcript", "").lower()
            at_scaling_limit = any(term in transcript_txt for term in [
                "scaling limit", "max replica", "limit reached", "cannot scale", "max capacity"
            ])
            if at_scaling_limit and "page_owner" in effect_tools:
                chosen_tool = "page_owner"
                chosen_args = {"service": run["incident"].get("service", "core-api"), "reason": "scaling_limit_reached"}

            run["chosenEffect"] = chosen_tool

            # Check if approval required
            if chosen_tool in approval_req:
                app_id = "app_" + gen_span_id()[:10]
                act_id = "act_" + gen_span_id()[:10]
                call_id = "call_" + gen_span_id()[:10]

                args_digest = compute_arguments_digest(chosen_args)
                approval_req_obj = {
                    "approvalId": app_id,
                    "actionId": act_id,
                    "toolName": chosen_tool,
                    "argumentsDigest": args_digest
                }

                run["pendingApproval"] = {
                    "approvalId": app_id,
                    "actionId": act_id,
                    "callId": call_id,
                    "toolName": chosen_tool,
                    "arguments": chosen_args
                }

                run["logicalActions"][act_id] = {
                    "actionId": act_id,
                    "callId": call_id,
                    "toolName": chosen_tool,
                    "phase": "effect",
                    "arguments": chosen_args,
                    "execSpanId": gen_span_id(),
                    "attempts": []
                }

                resp = {
                    "runId": run_id,
                    "status": "waiting",
                    "dispatches": [],
                    "approvals": [approval_req_obj]
                }
                run["receiptResponses"][receipt_id] = {"hash": body_hash, "response": resp}
                run["currentState"] = resp
                return resp
            else:
                # Safe effect without approval
                act_id = "act_" + gen_span_id()[:10]
                call_id = "call_" + gen_span_id()[:10]
                client_span_id = gen_span_id()

                effect_disp = {
                    "actionId": act_id,
                    "callId": call_id,
                    "phase": "effect",
                    "toolName": chosen_tool,
                    "arguments": chosen_args,
                    "attempt": 1,
                    "traceparent": format_traceparent(trace_id, client_span_id)
                }
                if tracestate:
                    effect_disp["tracestate"] = tracestate

                run["actionLog"].append(effect_disp)
                run["logicalActions"][act_id] = {
                    "actionId": act_id,
                    "callId": call_id,
                    "toolName": chosen_tool,
                    "phase": "effect",
                    "arguments": chosen_args,
                    "execSpanId": gen_span_id(),
                    "attempts": [{
                        "attempt": 1,
                        "clientSpanId": client_span_id
                    }]
                }

                resp = {
                    "runId": run_id,
                    "status": "waiting",
                    "dispatches": [effect_disp],
                    "approvals": []
                }
                run["receiptResponses"][receipt_id] = {"hash": body_hash, "response": resp}
                run["currentState"] = resp
                return resp

        # Effect was already dispatched; check if effect action has resolved
        effect_resolved = all(action_resolved(m) for m in effect_actions)
        if not effect_resolved:
            resp = {
                "runId": run_id,
                "status": "waiting",
                "dispatches": [],
                "approvals": []
            }
            run["receiptResponses"][receipt_id] = {"hash": body_hash, "response": resp}
            run["currentState"] = resp
            return resp

        # Terminal completed state!
        final_resp = {
            "runId": run_id,
            "status": "completed",
            "diagnosis": run["diagnosis"],
            "chosenEffect": run.get("chosenEffect", "scale_service"),
            "suppressed": [],
            "actionLog": run["actionLog"],
            "receiptLog": run["receiptLog"],
            "otlp": build_otlp_payload(run)
        }

        run["status"] = "completed"
        run["currentState"] = final_resp
        run["receiptResponses"][receipt_id] = {"hash": body_hash, "response": final_resp}
        return final_resp

store = StateStore()
