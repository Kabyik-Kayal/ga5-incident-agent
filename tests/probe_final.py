import sys
import json
import urllib.request
import urllib.error

effect_receipt = {
    "receiptId": "rec_live_02",
    "outcomes": [{
        "actionId": "act_b24e050c8e",
        "callId": "call_357bede13d",
        "attempt": 1,
        "status": 200,
        "resultClass": "scale_completed",
        "nonce": "nonce_live_456"
    }]
}

req_data = json.dumps(effect_receipt).encode("utf-8")
req = urllib.request.Request(
    "https://ga5-incident-agent-z8w6.onrender.com/v2/incidents/live-test-run-001/receipts",
    data=req_data,
    headers={"Content-Type": "application/json"}
)

try:
    with urllib.request.urlopen(req, timeout=15) as res:
        print("STATUS:", res.status)
        content = res.read().decode("utf-8")
        parsed = json.loads(content)
        print("STATUS FIELD:", parsed.get("status"))
        print("CHOSEN EFFECT:", parsed.get("chosenEffect"))
        print("ACTION LOG LEN:", len(parsed.get("actionLog", [])))
        print("RECEIPT LOG LEN:", len(parsed.get("receiptLog", [])))
        print("HAS OTLP:", "otlp" in parsed)
        print("SAMPLE SPAN NAMES:", [s["name"] for s in parsed.get("otlp", {}).get("resourceSpans", [{}])[0].get("scopeSpans", [{}])[0].get("spans", [])])
except urllib.error.HTTPError as e:
    print("HTTP ERROR:", e.code, e.read().decode("utf-8"))
except Exception as e:
    print("ERROR:", e)
