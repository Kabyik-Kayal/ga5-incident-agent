import os
import urllib.request
import json
import time

key = os.getenv("GEMINI_API_KEY")
print("KEY EXISTS:", bool(key))

# Test models on Google AI Studio
models_to_test = ["gemini-2.0-flash", "gemini-1.5-flash", "gemini-2.5-flash", "gemini-3.8-flash"]

for m in models_to_test:
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{m}:generateContent?key={key}"
    req = urllib.request.Request(
        url,
        data=json.dumps({"contents": [{"parts": [{"text": "say hi"}]}]}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            print(f"Model {m}: HTTP {res.status} in {round(time.time() - t0, 3)}s")
    except urllib.error.HTTPError as e:
        print(f"Model {m}: HTTP ERROR {e.code} in {round(time.time() - t0, 3)}s: {e.read().decode()[:120]}")
    except Exception as e:
        print(f"Model {m}: EXCEPTION {e} in {round(time.time() - t0, 3)}s")
