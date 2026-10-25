import urllib.request
import json

req = urllib.request.Request("https://ga5-incident-agent-z8w6.onrender.com/v2/incidents/live-test-run-001")
with urllib.request.urlopen(req) as res:
    data = json.loads(res.read().decode())
    spans = data["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
    chat_span = next(s for s in spans if s["name"] == "chat incident-plan")
    print("CHAT SPAN ATTRIBUTES:", chat_span["attributes"])
