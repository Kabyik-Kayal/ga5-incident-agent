# Observable Incident Triage Agent (`ga5-incident-agent/v2`)

A fully compliant, production-ready incident triage and response microservice built with **FastAPI** for TDS Assignment 4 ("Observable Incident Triage: diagnose before acting").

---

## 🎯 Architecture & Workflow

```text
Grader (Automated Evaluation)
       │
       ├── 1. POST /v2/incidents ──► [ AI Incident Planner ]
       │                                     │
       │   ◄── status: waiting ──────────────┴── Emits 1-3 Diagnostic Dispatches
       │       with W3C traceparent
       │
       ├── 2. POST /v2/incidents/{runId}/receipts ──► [ State Machine ]
       │                                                      │
       │       [ 503 Retry ] ◄────────────────────────────────┤
       │       (attempt: 2 with new client span ID)          │
       │                                                      ├── Safe Effect (e.g. scale_service or page_owner)
       │                                                      │   ◄── Emits effect dispatch
       │                                                      │
       │       [ Destructive Effect ] ◄───────────────────────┘
       │       (rollback_deployment / disable_feature)
       │       ◄── status: waiting, approvals: [SHA-256 digest]
       │
       ├── 3. POST approval receipt ──► Dispatches approved effect
       │
       └── 4. Final Receipt ──► 200 OK with:
                                ├── status: "completed"
                                ├── actionLog
                                ├── receiptLog
                                └── otlp (Full OpenTelemetry ResourceSpans)
```

---

## 📁 Repository Structure

```
ga5-incident-agent/
├── app/
│   ├── __init__.py
│   ├── main.py          # FastAPI application & HTTP routing
│   ├── models.py        # Pydantic schemas for requests, dispatches, & receipts
│   ├── state.py         # State machine, idempotency, retry, & conflict handling
│   ├── planner.py       # AI diagnostic planner + sub-millisecond fallback
│   ├── telemetry.py     # W3C trace context & OTLP ResourceSpans generator
│   └── digest.py        # SHA-256 argument digest for approval gate
├── tests/
│   └── test_agent.py    # Test suite for full triage, approvals, & telemetry
├── Dockerfile           # Production container configuration
├── Procfile             # Web server entrypoint
├── render.yaml          # Render blueprint configuration
├── requirements.txt     # Python dependencies
└── .gitignore           # Git ignore list
```

---

## 🚀 One-Click Deploy on Render

### Step 1: Push This Repo to GitHub
Run the following in your terminal:
```bash
git remote add origin https://github.com/<YOUR_GITHUB_USERNAME>/ga5-incident-agent.git
git push -u origin main
```

### Step 2: Create Web Service on Render
1. Go to [Render Dashboard](https://dashboard.render.com/).
2. Click **New +** $\to$ **Web Service**.
3. Select your GitHub repository: `ga5-incident-agent`.
4. Fill in the settings:
   - **Name**: `ga5-incident-agent`
   - **Environment**: `Python`
   - **Region**: `Oregon (US West)` (or closest to you)
   - **Branch**: `main`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - **Plan**: `Free`

### Step 3: Configure Environment Variables
Under the **Environment Variables** tab, add:
- `GEMINI_API_KEY`: *(Your Google AI Studio API key - free tier)*
- `GEMINI_MODEL`: `gemini-2.0-flash`
*(Or set `OPENAI_API_KEY` / `GROQ_API_KEY` if preferred)*

### Step 4: Submit to Grader
Once deployed, copy your Render URL:
```
https://ga5-incident-agent-xxxx.onrender.com
```
Paste this URL directly into the assignment portal and click **Check**!

---

## 🧪 Local Testing

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run unit tests
pytest -v

# 3. Start local development server
uvicorn app.main:app --reload --port 8000
```

---

## 🛡️ Grading Safeguards Implemented

- **Sensitive Redaction**: The `sensitive` object is completely stripped before planning and omitted from all telemetry spans and responses.
- **Strict Idempotency**: Identical requests return the exact stored state without calling the AI model again.
- **Conflict Detection (HTTP 409)**: Requests with the same `runId` or `receiptId` but differing payloads return HTTP 409 Conflict.
- **503 Resilience**: Automatically manages single retry on HTTP 503 with resend count tracking.
- **Scaling Limit Awareness**: Automatically detects when a service is at max capacity and dispatches `page_owner` instead of `scale_service`.
- **Approval Gate**: Implements key-sorted compact JSON SHA-256 argument digest verification.
- **OTLP Telemetry Tree**: Validated against W3C trace context with SERVER, CLIENT, and INTERNAL spans, link aggregation on `incident.join`, and approval gate tracking.
