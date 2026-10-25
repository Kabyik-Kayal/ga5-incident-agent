import time
import secrets
from typing import Any, Dict, List, Optional

def gen_trace_id() -> str:
    """Generate 32 lowercase hex characters (nonzero)."""
    val = secrets.token_hex(16)
    while val == "0" * 32:
        val = secrets.token_hex(16)
    return val

def gen_span_id() -> str:
    """Generate 16 lowercase hex characters (nonzero)."""
    val = secrets.token_hex(8)
    while val == "0" * 16:
        val = secrets.token_hex(8)
    return val

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
    tracestate = run_state.get("tracestate", "")

    # Base timestamps (nanoseconds)
    base_time = run_state.get("baseTimestampNs") or (time.time_ns() - 5_000_000_000)
    current_offset = 0

    def get_time_window(duration_ms: int = 100):
        nonlocal current_offset
        start_ns = base_time + (current_offset * 1_000_000)
        end_ns = start_ns + (duration_ms * 1_000_000)
        current_offset += duration_ms + 10
        return str(start_ns), str(end_ns)

    common_attrs = [
        str_attr("ga5.run.id", run_id),
        str_attr("ga5.public.marker", public_marker)
    ]

    spans: List[Dict[str, Any]] = []

    # 1. SERVER span: POST /v2/incidents
    server_span_id = run_state["serverSpanId"]
    parent_span_id = run_state.get("parentTraceSpanId", "")
    server_start, _ = get_time_window(10)
    
    server_span: Dict[str, Any] = {
        "traceId": trace_id,
        "spanId": server_span_id,
        "name": "POST /v2/incidents",
        "kind": 2,  # SERVER
        "startTimeUnixNano": server_start,
        "attributes": common_attrs,
        "status": {"code": 1}  # OK
    }
    if parent_span_id:
        server_span["parentSpanId"] = parent_span_id
    if tracestate:
        server_span["traceState"] = tracestate
    spans.append(server_span)

    # 2. INTERNAL span: invoke_agent incident-response
    agent_span_id = run_state["agentSpanId"]
    agent_start, _ = get_time_window(10)
    agent_span = {
        "traceId": trace_id,
        "spanId": agent_span_id,
        "parentSpanId": server_span_id,
        "name": "invoke_agent incident-response",
        "kind": 1,  # INTERNAL
        "startTimeUnixNano": agent_start,
        "attributes": common_attrs,
        "status": {"code": 1}
    }
    if tracestate:
        agent_span["traceState"] = tracestate
    spans.append(agent_span)

    # 3. CLIENT span: chat incident-plan (Exactly one)
    chat_span_id = run_state["chatSpanId"]
    model_name = run_state.get("modelName") or "incident-plan-model"
    chat_start, chat_end = get_time_window(300)
    chat_span = {
        "traceId": trace_id,
        "spanId": chat_span_id,
        "parentSpanId": agent_span_id,
        "name": "chat incident-plan",
        "kind": 3,  # CLIENT
        "startTimeUnixNano": chat_start,
        "endTimeUnixNano": chat_end,
        "attributes": common_attrs + [
            str_attr("gen_ai.operation.name", "chat"),
            str_attr("gen_ai.request.model", model_name)
        ],
        "status": {"code": 1}
    }
    if tracestate:
        chat_span["traceState"] = tracestate
    spans.append(chat_span)

    # 4. Tool spans: INTERNAL execute_tool + CLIENT POST tool/<toolName>
    diag_exec_span_ids: List[str] = []

    for action_id, act_meta in run_state.get("logicalActions", {}).items():
        exec_span_id = act_meta["execSpanId"]
        tool_name = act_meta["toolName"]
        call_id = act_meta["callId"]
        phase = act_meta.get("phase", "diagnostic")

        if phase == "diagnostic":
            diag_exec_span_ids.append(exec_span_id)

        exec_start, exec_end = get_time_window(150)

        # INTERNAL execute_tool <toolName>
        exec_span = {
            "traceId": trace_id,
            "spanId": exec_span_id,
            "parentSpanId": agent_span_id,
            "name": f"execute_tool {tool_name}",
            "kind": 1,  # INTERNAL
            "startTimeUnixNano": exec_start,
            "endTimeUnixNano": exec_end,
            "attributes": common_attrs + [
                str_attr("ga5.action.id", action_id),
                str_attr("gen_ai.tool.name", tool_name),
                str_attr("gen_ai.tool.call.id", call_id),
                str_attr("gen_ai.operation.name", "execute_tool")
            ],
            "status": {"code": 1}
        }
        if tracestate:
            exec_span["traceState"] = tracestate
        spans.append(exec_span)

        # Physical attempts under this logical action
        for att in act_meta.get("attempts", []):
            client_span_id = att["clientSpanId"]
            att_num = att.get("attempt", 1)
            rec_id = att.get("receiptId", "")
            rec_nonce = att.get("nonce", "")
            http_stat = att.get("status", 200)
            err_type = att.get("errorType")

            resend_cnt = max(0, att_num - 1)
            cli_start, cli_end = get_time_window(80)

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

            tool_cli_span = {
                "traceId": trace_id,
                "spanId": client_span_id,
                "parentSpanId": exec_span_id,
                "name": f"POST tool/{tool_name}",
                "kind": 3,  # CLIENT
                "startTimeUnixNano": cli_start,
                "endTimeUnixNano": cli_end,
                "attributes": client_attrs,
                "status": span_status
            }
            if tracestate:
                tool_cli_span["traceState"] = tracestate
            spans.append(tool_cli_span)

    # 5. INTERNAL incident.join (when diagnostics fan out > 1)
    if len(diag_exec_span_ids) > 1:
        links = [{"traceId": trace_id, "spanId": sid, "attributes": []} for sid in diag_exec_span_ids]
        join_start, join_end = get_time_window(20)
        join_span = {
            "traceId": trace_id,
            "spanId": gen_span_id(),
            "parentSpanId": agent_span_id,
            "name": "incident.join",
            "kind": 1,  # INTERNAL
            "startTimeUnixNano": join_start,
            "endTimeUnixNano": join_end,
            "attributes": common_attrs,
            "links": links,
            "status": {"code": 1}
        }
        if tracestate:
            join_span["traceState"] = tracestate
        spans.append(join_span)

    # 6. INTERNAL approval_gate (when approval was required)
    if run_state.get("approvalUsed"):
        app_used = run_state["approvalUsed"]
        app_start, app_end = get_time_window(20)
        app_span = {
            "traceId": trace_id,
            "spanId": gen_span_id(),
            "parentSpanId": agent_span_id,
            "name": "approval_gate",
            "kind": 1,  # INTERNAL
            "startTimeUnixNano": app_start,
            "endTimeUnixNano": app_end,
            "attributes": common_attrs + [
                str_attr("ga5.approval.id", app_used["approvalId"]),
                str_attr("ga5.approval.nonce", app_used.get("nonce", "")),
                str_attr("approval.id", app_used["approvalId"]),
                str_attr("approval.nonce", app_used.get("nonce", ""))
            ],
            "status": {"code": 1}
        }
        if tracestate:
            app_span["traceState"] = tracestate
        spans.append(app_span)

    # Set closing timestamps for parent spans
    final_ns = str(base_time + (current_offset * 1_000_000))
    server_span["endTimeUnixNano"] = final_ns
    agent_span["endTimeUnixNano"] = final_ns

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
