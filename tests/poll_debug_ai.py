import urllib.request
import json
import time

for _ in range(10):
    try:
        url = "https://ga5-incident-agent-z8w6.onrender.com/debug/test-ai"
        with urllib.request.urlopen(url, timeout=10) as res:
            if res.status == 200:
                print("DEBUG TEST AI RESULTS:")
                print(json.dumps(json.loads(res.read().decode()), indent=2))
                break
    except Exception as e:
        print("Waiting for deployment...", e)
        time.sleep(5)
