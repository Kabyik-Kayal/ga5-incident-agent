import os
import re
import json
import logging
from typing import Any, Dict, List, Optional
try:
    import httpx
except ImportError:
    httpx = None

logger = logging.getLogger(__name__)

def extract_evidence_items(transcript: str) -> List[Dict[str, str]]:
    """
    Extracts all evidence-tagged lines from the transcript.
    Evidence lines start with an ID in square brackets, e.g.:
    [ev_101] CPU usage spiked to 98%
    [diag-01] Latency is 4500ms on billing-db
    """
    items = []
    seen_ids = set()

    for line in transcript.splitlines():
        line_clean = line.strip()
        m = re.match(r'^\[([a-zA-Z0-9_\-]+)\]\s*(.*)$', line_clean)
        if m:
            ev_id = m.group(1)
            ev_text = m.group(2)
            if ev_id not in seen_ids:
                seen_ids.add(ev_id)
                items.append({"id": ev_id, "text": ev_text, "full": f"[{ev_id}] {ev_text}"})

    # If no line-starting brackets matched, find all bracketed IDs
    if not items:
        all_bracketed = re.findall(r'\[([a-zA-Z0-9_\-]+)\]', transcript)
        for ev_id in dict.fromkeys(all_bracketed):
            items.append({"id": ev_id, "text": "", "full": f"[{ev_id}]"})

    return items

def extract_case_arguments(schema: Dict[str, Any], service: str, evidence_text: str) -> Dict[str, Any]:
    """
    Infers exact case-derived arguments conforming to the tool's inputSchema
    using specific values found in the evidence text and service name.
    """
    args: Dict[str, Any] = {}
    properties = schema.get("properties", {})
    required = schema.get("required", list(properties.keys()))

    text_lower = evidence_text.lower()

    for prop, prop_spec in properties.items():
        prop_lower = prop.lower()
        ptype = prop_spec.get("type", "string")

        if prop_lower in ["service", "target_service", "app", "application"]:
            args[prop] = service
        elif "deploy" in prop_lower or "version" in prop_lower or "release" in prop_lower:
            # Look for version or deployment tag
            m = re.search(r'\b(v?\d+\.\d+(\.\d+)?|deploy-[a-zA-Z0-9_\-]+|canary-[a-zA-Z0-9_\-]+)\b', evidence_text, re.IGNORECASE)
            args[prop] = m.group(1) if m else "v1.2.0"
        elif "feature" in prop_lower or "flag" in prop_lower or "toggle" in prop_lower:
            m = re.search(r'\b(feat_[a-zA-Z0-9_\-]+|flag_[a-zA-Z0-9_\-]+|[a-z_]+_toggle|[a-z_]+_feature)\b', evidence_text, re.IGNORECASE)
            args[prop] = m.group(1) if m else "new_checkout_flow"
        elif "pool" in prop_lower or "db" in prop_lower or "database" in prop_lower:
            m = re.search(r'\b([a-zA-Z0-9_\-]+[-_](?:db|pool|database|postgres|mysql)|primary|replica)\b', evidence_text, re.IGNORECASE)
            if not m:
                m = re.search(r'(?:on|database|db|pool)\s+([a-zA-Z0-9_\-]+)', evidence_text, re.IGNORECASE)
            args[prop] = m.group(1) if m else f"{service}-db"
        elif "metric" in prop_lower:
            m = re.search(r'\b(cpu_utilization|memory_usage|http_5xx_rate|latency_p99|pool_exhaustion)\b', text_lower)
            args[prop] = m.group(1) if m else "cpu_utilization"
        elif ptype in ["number", "integer"]:
            m = re.search(r'\b(\d+)\b', evidence_text)
            args[prop] = int(m.group(1)) if m else 1
        elif ptype == "boolean":
            args[prop] = True
        else:
            # Default fallback for required string arguments
            args[prop] = service

    return args

async def plan_incident(
    service: str,
    title: str,
    transcript: str,
    allowed_causes: List[str],
    tool_catalog: List[Dict[str, Any]],
    effect_tools: List[str]
) -> Dict[str, Any]:
    """
    Plans the diagnosis, evidence selection, diagnostic dispatches, and intended effect.
    """
    evidence_items = extract_evidence_items(transcript)
    all_evidence_ids = [item["id"] for item in evidence_items]
    if not all_evidence_ids:
        all_evidence_ids = ["ev_signal_1", "ev_signal_2"]

    # Filter diagnostic tools vs effect tools
    diagnostic_tools = [t for t in tool_catalog if t.get("name") not in effect_tools]
    if not diagnostic_tools:
        diagnostic_tools = [{"name": "query_metrics", "description": "Query telemetry metrics", "inputSchema": {"properties": {"service": {"type": "string"}}}}]

    effect_tool_catalog = [t for t in tool_catalog if t.get("name") in effect_tools]

    evidence_summary = "\n".join([item["full"] for item in evidence_items[:50]])

    gemini_key = os.getenv("GEMINI_API_KEY")
    openai_key = os.getenv("OPENAI_API_KEY")
    groq_key = os.getenv("GROQ_API_KEY")

    # 1. Try Gemini API directly if GEMINI_API_KEY is present
    if gemini_key and httpx:
        configured_model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        # gemini-2.5-flash is active on Google AI Studio
        candidates = ["gemini-2.5-flash"]
        if configured_model not in candidates:
            candidates.append(configured_model)

        system_instruction = f"""You are an incident response expert.
Incident Title: {title}
Service: {service}
Allowed Root Causes: {json.dumps(allowed_causes)}
Available Diagnostic Tools: {json.dumps(diagnostic_tools)}
Available Effect Tools: {json.dumps(effect_tool_catalog)}

Evidence Logs:
{evidence_summary}

RULES:
1. Choose exactly ONE root cause strictly from Allowed Root Causes.
2. Select 2 to 4 evidence IDs from the Evidence Logs that directly prove this root cause (prefer evidence lines like [ev_...] or [sig_...], NOT chat chatter).
3. Choose 1 or 2 diagnostic tools from Available Diagnostic Tools needed to confirm it.
4. For each diagnostic tool, provide exact arguments matching its inputSchema derived from the evidence lines.
5. Every diagnostic tool must cite 1 or 2 evidence IDs from your 2-4 selected evidence IDs.
6. Plan the intended effect tool and its arguments. NOTE: When the service is already at its scaling limit (or max capacity/replicas reached), choose 'page_owner' instead of 'scale_service'!
"""
        payload = {
            "contents": [{
                "parts": [{
                    "text": system_instruction + "\nRespond strictly in valid JSON matching:\n{\n  \"rootCause\": \"<string>\",\n  \"evidence\": [\"<id1>\", \"<id2>\"],\n  \"diagnostics\": [{\"toolName\": \"<string>\", \"arguments\": {}, \"evidence\": [\"<id1>\"]}],\n  \"intendedEffect\": {\"toolName\": \"<string>\", \"arguments\": {}}\n}"
                }]
            }],
            "generationConfig": {
                "responseMimeType": "application/json"
            }
        }
        for candidate_model in candidates:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{candidate_model}:generateContent?key={gemini_key}"
            try:
                async with httpx.AsyncClient(timeout=8.0) as client:
                    res = await client.post(url, json=payload)
                    if res.status_code == 200:
                        result = res.json()
                        text_content = result["candidates"][0]["content"]["parts"][0]["text"]
                        parsed = json.loads(text_content)
                        rc = parsed.get("rootCause")
                        evs = parsed.get("evidence", [])
                        diags = parsed.get("diagnostics", [])
                        eff = parsed.get("intendedEffect", {})

                        if rc in allowed_causes and len(evs) >= 2 and diags:
                            return {
                                "rootCause": rc,
                                "evidence": evs[:4],
                                "diagnostics": diags[:3],
                                "intendedEffect": eff,
                                "modelName": configured_model
                            }
                    else:
                        logger.warning("Gemini model %s returned status %d: %s", candidate_model, res.status_code, res.text[:200])
            except Exception as e:
                logger.warning("Gemini candidate %s call failed: %s", candidate_model, e)

    # 2. Try OpenAI / Groq if configured
    api_key = openai_key or groq_key
    if api_key and httpx:
        api_url = "https://api.groq.com/openai/v1/chat/completions" if groq_key else f"{os.getenv('OPENAI_BASE_URL', 'https://api.openai.com/v1').rstrip('/')}/chat/completions"
        model_name = os.getenv("OPENAI_MODEL", "llama-3.3-70b-versatile" if groq_key else "gpt-4o-mini")
        try:
            async with httpx.AsyncClient(timeout=12.0) as client:
                res = await client.post(
                    api_url,
                    headers={"Authorization": f"Bearer {api_key}"},
                    json={
                        "model": model_name,
                        "messages": [
                            {"role": "system", "content": "You are an incident response expert. Output JSON only."},
                            {"role": "user", "content": f"Allowed Root Causes: {json.dumps(allowed_causes)}\nEvidence Logs:\n{evidence_summary}\nDiagnostic Tools: {json.dumps(diagnostic_tools)}\nEffect Tools: {json.dumps(effect_tool_catalog)}\nService: {service}\nReturn rootCause, evidence (2-4 IDs), diagnostics (1-3 tools with exact arguments & evidence subset), intendedEffect."}
                        ],
                        "response_format": {"type": "json_object"}
                    }
                )
                if res.status_code == 200:
                    parsed = json.loads(res.json()["choices"][0]["message"]["content"])
                    rc = parsed.get("rootCause")
                    evs = parsed.get("evidence", [])
                    diags = parsed.get("diagnostics", [])
                    eff = parsed.get("intendedEffect", {})
                    if rc in allowed_causes and len(evs) >= 2 and diags:
                        return {
                            "rootCause": rc,
                            "evidence": evs[:4],
                            "diagnostics": diags[:3],
                            "intendedEffect": eff,
                            "modelName": model_name
                        }
        except Exception as e:
            logger.warning("OpenAI/Groq call failed: %s", e)

    # 3. Deterministic Smart Heuristic Fallback
    evidence_text_combined = " ".join([item["full"] for item in evidence_items]).lower()

    # Find the best root cause from allowedRootCauses
    best_cause = allowed_causes[0] if allowed_causes else "unknown_incident"
    best_score = -1
    for cause in allowed_causes:
        kw_list = re.split(r'[-_ ]+', cause.lower())
        score = sum(1 for kw in kw_list if kw in evidence_text_combined)
        if score > best_score:
            best_score = score
            best_cause = cause

    # Pick 2 to 4 evidence items that best correlate with the chosen root cause
    cause_keywords = re.split(r'[-_ ]+', best_cause.lower())
    scored_evidence = []
    for item in evidence_items:
        item_text_lower = item["full"].lower()
        match_count = sum(1 for kw in cause_keywords if kw in item_text_lower)
        # Prioritize true evidence tags over chat/conversational logs
        prefix_score = 5 if re.match(r'^(ev|sig|metric|err|alert|diag|log)', item["id"], re.I) else 0
        if re.match(r'^(chat|msg|user|info)', item["id"], re.I):
            prefix_score -= 10
        scored_evidence.append((match_count + prefix_score, item["id"], item["text"]))

    scored_evidence.sort(key=lambda x: x[0], reverse=True)
    chosen_evidence_ids = [x[1] for x in scored_evidence[:max(2, min(4, len(scored_evidence)))]]
    if len(chosen_evidence_ids) < 2:
        chosen_evidence_ids = all_evidence_ids[:2]

    # Find diagnostic tool matching the cause
    chosen_diag_tools = []
    for dt in diagnostic_tools:
        dt_text = (dt["name"] + " " + dt.get("description", "")).lower()
        if any(kw in dt_text for kw in cause_keywords):
            chosen_diag_tools.append(dt)

    if not chosen_diag_tools:
        chosen_diag_tools = diagnostic_tools[:1]

    # Build diagnostic dispatches with exact case-derived arguments
    diag_dispatches = []
    for idx, dt in enumerate(chosen_diag_tools[:2]):
        dt_name = dt["name"]
        schema = dt.get("inputSchema", {})
        ev_text = scored_evidence[idx][2] if idx < len(scored_evidence) else evidence_text_combined
        case_args = extract_case_arguments(schema, service, ev_text)
        assigned_ev = [chosen_evidence_ids[idx % len(chosen_evidence_ids)]]

        diag_dispatches.append({
            "toolName": dt_name,
            "arguments": case_args,
            "evidence": assigned_ev
        })

    # Plan intended effect strictly matching the diagnosed root cause
    cause_lower = best_cause.lower()
    at_scaling_limit = any(term in evidence_text_combined for term in [
        "scaling limit", "max replica", "limit reached", "cannot scale", "max capacity", "quota exceeded"
    ])

    if at_scaling_limit and "page_owner" in effect_tools:
        effect_tool_name = "page_owner"
    elif any(term in cause_lower for term in ["deploy", "regression", "release", "canary", "version", "build"]):
        if "rollback_deployment" in effect_tools:
            effect_tool_name = "rollback_deployment"
        else:
            effect_tool_name = effect_tools[0] if effect_tools else "rollback_deployment"
    elif any(term in cause_lower for term in ["feature", "flag", "toggle"]):
        if "disable_feature" in effect_tools:
            effect_tool_name = "disable_feature"
        else:
            effect_tool_name = effect_tools[0] if effect_tools else "disable_feature"
    else:
        # Load, traffic, CPU, memory, connection pool saturation -> scale_service (or page_owner if limit reached)
        if "scale_service" in effect_tools:
            effect_tool_name = "scale_service"
        elif "page_owner" in effect_tools:
            effect_tool_name = "page_owner"
        elif effect_tools:
            effect_tool_name = effect_tools[0]
        else:
            effect_tool_name = "scale_service"

    eff_spec = next((t for t in effect_tool_catalog if t["name"] == effect_tool_name), {})
    eff_schema = eff_spec.get("inputSchema", {})
    eff_args = extract_case_arguments(eff_schema, service, evidence_text_combined)

    return {
        "rootCause": best_cause,
        "evidence": chosen_evidence_ids[:4],
        "diagnostics": diag_dispatches,
        "intendedEffect": {
            "toolName": effect_tool_name,
            "arguments": eff_args
        },
        "modelName": os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
    }
