import secrets
from typing import Any, Dict, List, Optional

def gen_trace_id() -> str:
    """Generate 32 lowercase hex characters (nonzero)."""
    return secrets.token_hex(16)

def gen_span_id() -> str:
    """Generate 16 lowercase hex characters (nonzero)."""
    return secrets.token_hex(8)

def format_traceparent(trace_id: str, span_id: str) -> str:
    """W3C traceparent string: 00-{trace_id}-{span_id}-01"""
    return f"00-{trace_id}-{span_id}-01"

def str_attr(key: str, val: Any) -> Dict[str, Any]:
    return {"key": key, "value": {"stringValue": str(val)}}

def int_attr(key: str, val: int) -> Dict[str, Any]:
    return {"key": key, "value": {"intValue": int(val)}}

def build_otlp_payload(run_state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Constructs an OpenTelemetry ResourceSpans object adhering strictly to the
    GA5 Incident Agent specification.
    """
    trace_id = run_state["traceId"]
    public_marker = run_state.get("publicMarker", "public")
    run_id = run_state["runId"]

    common_attrs = [
        str_attr("ga5.run.id", run_id),
        str_attr("ga5.public.marker", public_marker)
    ]

    spans: List[Dict[str, Any]] = []

    # 1. SERVER span: POST /v2/incidents
    server_span_id = run_state["serverSpanId"]
    parent_span_id = run_state.get("parentTraceSpanId", "")
    server_span: Dict[str, Any] = {
        "traceId": trace_id,
        "spanId": server_span_id,
        "name": "POST /v2/incidents",
        "kind": 2,  # SERVER
        "attributes": common_attrs,
        "status": {"code": 1}  # OK
    }
    if parent_span_id:
        server_span["parentSpanId"] = parent_span_id
    spans.append(server_span)

    # 2. INTERNAL span: invoke_agent incident-response
    agent_span_id = run_state["agentSpanId"]
    spans.append({
        "traceId": trace_id,
        "spanId": agent_span_id,
        "parentSpanId": server_span_id,
        "name": "invoke_agent incident-response",
        "kind": 1,  # INTERNAL
        "attributes": common_attrs,
        "status": {"code": 1}
    })

    # 3. CLIENT span: chat incident-plan (Exactly one)
    chat_span_id = run_state["chatSpanId"]
    model_name = run_state.get("modelName") or "incident-plan-model"
    spans.append({
        "traceId": trace_id,
        "spanId": chat_span_id,
        "parentSpanId": agent_span_id,
        "name": "chat incident-plan",
        "kind": 3,  # CLIENT
        "attributes": common_attrs + [
            str_attr("gen_ai.operation.name", "chat"),
            str_attr("gen_ai.request.model", model_name)
        ],
        "status": {"code": 1}
    })

    # 4. Tool spans: INTERNAL execute_tool + CLIENT POST tool/<toolName>
    diag_exec_span_ids: List[str] = []

    for action_id, act_meta in run_state.get("logicalActions", {}).items():
        exec_span_id = act_meta["execSpanId"]
        tool_name = act_meta["toolName"]
        call_id = act_meta["callId"]
        phase = act_meta.get("phase", "diagnostic")

        if phase == "diagnostic":
            diag_exec_span_ids.append(exec_span_id)

        # INTERNAL execute_tool <toolName>
        spans.append({
            "traceId": trace_id,
            "spanId": exec_span_id,
            "parentSpanId": agent_span_id,
            "name": f"execute_tool {tool_name}",
            "kind": 1,  # INTERNAL
            "attributes": common_attrs + [
                str_attr("ga5.action.id", action_id),
                str_attr("gen_ai.tool.name", tool_name),
                str_attr("gen_ai.tool.call.id", call_id),
                str_attr("gen_ai.operation.name", "execute_tool")
            ],
            "status": {"code": 1}
        })

        # Physical attempts under this logical action
        for att in act_meta.get("attempts", []):
            client_span_id = att["clientSpanId"]
            att_num = att.get("attempt", 1)
            rec_id = att.get("receiptId", "")
            rec_nonce = att.get("nonce", "")
            http_stat = att.get("status", 200)
            err_type = att.get("errorType")

            resend_cnt = max(0, att_num - 1)

            client_attrs = common_attrs + [
                str_attr("ga5.action.id", action_id),
                int_attr("ga5.attempt", att_num),
                str_attr("ga5.receipt.id", rec_id),
                str_attr("ga5.receipt.nonce", rec_nonce),
                str_attr("http.request.method", "POST"),
                int_attr("http.request.resend_count", resend_cnt)
            ]

            span_status = {"code": 1}  # OK

            if http_stat == 503:
                span_status = {"code": 2}  # ERROR
                client_attrs.append(str_attr("error.type", "503"))
            elif err_type == "timeout" or http_stat == 0:
                span_status = {"code": 2}  # ERROR
                client_attrs.append(str_attr("error.type", "timeout"))

            spans.append({
                "traceId": trace_id,
                "spanId": client_span_id,
                "parentSpanId": exec_span_id,
                "name": f"POST tool/{tool_name}",
                "kind": 3,  # CLIENT
                "attributes": client_attrs,
                "status": span_status
            })

    # 5. INTERNAL incident.join (when diagnostics fan out > 1)
    if len(diag_exec_span_ids) > 1:
        links = [{"traceId": trace_id, "spanId": sid, "attributes": []} for sid in diag_exec_span_ids]
        spans.append({
            "traceId": trace_id,
            "spanId": gen_span_id(),
            "parentSpanId": agent_span_id,
            "name": "incident.join",
            "kind": 1,  # INTERNAL
            "attributes": common_attrs,
            "links": links,
            "status": {"code": 1}
        })

    # 6. INTERNAL approval_gate (when approval is required)
    if run_state.get("approvalUsed"):
        app_used = run_state["approvalUsed"]
        spans.append({
            "traceId": trace_id,
            "spanId": gen_span_id(),
            "parentSpanId": agent_span_id,
            "name": "approval_gate",
            "kind": 1,  # INTERNAL
            "attributes": common_attrs + [
                str_attr("ga5.approval.id", app_used["approvalId"]),
                str_attr("ga5.approval.nonce", app_used.get("nonce", ""))
            ],
            "status": {"code": 1}
        })

    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [str_attr("service.name", "incident-agent")]
                },
                "scopeSpans": [
                    {
                        "scope": {"name": "ga5-incident-agent", "version": "2.0"},
                        "spans": spans
                    }
                ]
            }
        ]
    }
