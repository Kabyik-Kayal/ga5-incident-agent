import sys
import json
import urllib.request
import urllib.error

payload = {
    "profile": "ga5-incident-agent/v2",
    "runId": "live-test-run-001",
    "agentName": "incident-response",
    "publicMarker": "test-marker-live",
    "sensitive": {"accessToken": "top_secret_token"},
    "incident": {
        "incidentId": "inc_live_1",
        "title": "Database Connection Pool Exhaustion",
        "service": "billing-service",
        "severity": "SEV-1",
        "transcript": "[ev_01] connection pool 100/100 exhausted\n[ev_02] latency 4500ms on billing_db",
        "allowedRootCauses": ["connection_pool_exhaustion", "cpu_saturation"]
    },
    "toolCatalog": [
        {
            "name": "check_pool_status",
            "description": "Inspect database connection pool",
            "inputSchema": {"type": "object", "properties": {"service": {"type": "string"}}}
        },
        {
            "name": "scale_service",
            "description": "Scale instances",
            "inputSchema": {"type": "object", "properties": {"service": {"type": "string"}}}
        }
    ],
    "policy": {
        "maximumDiagnostics": 2,
        "effectTools": ["scale_service"],
        "approvalRequiredFor": [],
        "doNotExport": ["accessToken"]
    }
}

req_data = json.dumps(payload).encode("utf-8")
req = urllib.request.Request(
    "https://ga5-incident-agent-z8w6.onrender.com/v2/incidents",
    data=req_data,
    headers={"Content-Type": "application/json"}
)

try:
    with urllib.request.urlopen(req, timeout=15) as res:
        print("STATUS:", res.status)
        print("RESPONSE:", res.read().decode("utf-8"))
except urllib.error.HTTPError as e:
    print("HTTP ERROR:", e.code, e.read().decode("utf-8"))
except Exception as e:
    print("ERROR:", e)
