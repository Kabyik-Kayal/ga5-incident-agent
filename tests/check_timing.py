import urllib.request
import json
import time

payload = {
    "profile": "ga5-incident-agent/v2",
    "runId": f"timing-test-{int(time.time())}",
    "agentName": "incident-response",
    "publicMarker": "marker-timing",
    "incident": {
        "title": "CPU Overload",
        "service": "orders-service",
        "transcript": "[ev_01] cpu saturation at 99%\n[ev_02] worker timeout",
        "allowedRootCauses": ["cpu_saturation"]
    },
    "toolCatalog": [{"name": "check_cpu", "inputSchema": {"properties": {"service": {"type": "string"}}}}],
    "policy": {"maximumDiagnostics": 1, "effectTools": ["scale_service"]}
}

t0 = time.time()
req = urllib.request.Request(
    "https://ga5-incident-agent-z8w6.onrender.com/v2/incidents",
    data=json.dumps(payload).encode(),
    headers={"Content-Type": "application/json"}
)
with urllib.request.urlopen(req) as res:
    print("STATUS:", res.status)
    print("TIME:", round(time.time() - t0, 3), "seconds")
