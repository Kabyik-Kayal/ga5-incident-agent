import sys
import json
import urllib.request
import urllib.error

# Outcome receipt for probe run
receipt = {
    "receiptId": "rec_live_01",
    "outcomes": [{
        "actionId": "act_e08475efaf",
        "callId": "call_b36f38902e",
        "attempt": 1,
        "status": 200,
        "resultClass": "diagnosis_confirmed",
        "nonce": "nonce_live_123"
    }]
}

req_data = json.dumps(receipt).encode("utf-8")
req = urllib.request.Request(
    "https://ga5-incident-agent-z8w6.onrender.com/v2/incidents/live-test-run-001/receipts",
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
