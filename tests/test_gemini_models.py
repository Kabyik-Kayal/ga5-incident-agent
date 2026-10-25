import os
import time
import httpx
import asyncio

async def test_endpoint(model):
    key = os.getenv("GEMINI_API_KEY")
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
    payload = {"contents": [{"parts": [{"text": "hi"}]}]}
    t0 = time.time()
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            res = await client.post(url, json=payload)
            print(f"Model {model}: HTTP {res.status_code} in {round(time.time() - t0, 3)}s")
        except Exception as e:
            print(f"Model {model}: EXCEPTION {type(e).__name__} in {round(time.time() - t0, 3)}s")

# Let's test on Render by creating a small test script or checking Render logs
