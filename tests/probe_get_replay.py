import sys
import json
import urllib.request
import urllib.error

# 1. GET /v2/incidents/{runId}
req = urllib.request.Request("https://ga5-incident-agent-z8w6.onrender.com/v2/incidents/live-test-run-001")
with urllib.request.urlopen(req, timeout=15) as res:
    data = json.loads(res.read().decode("utf-8"))
    print("GET STATUS:", data.get("status"), "EFFECT:", data.get("chosenEffect"))

# 2. Conflict test: same runId with altered payload -> must return 409
payload_conflict = {
    "profile": "ga5-incident-agent/v2",
    "runId": "live-test-run-001",
    "publicMarker": "different-marker"
}
req_conflict = urllib.request.Request(
    "https://ga5-incident-agent-z8w6.onrender.com/v2/incidents",
    data=json.dumps(payload_conflict).encode("utf-8"),
    headers={"Content-Type": "application/json"}
)
try:
    urllib.request.urlopen(req_conflict, timeout=15)
    print("CONFLICT FAILED!")
except urllib.error.HTTPError as e:
    print("CONFLICT TEST (Expect 409):", e.code)
