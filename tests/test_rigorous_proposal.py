import urllib.request
import json
import time

test_incident = {
    "profile": "ga5-incident-agent/v2",
    "runId": f"deep-test-{int(time.time())}",
    "agentName": "incident-response",
    "publicMarker": "audit-marker-rigorous",
    "sensitive": {"accessToken": "SECRET_SHOULD_NEVER_LEAK"},
    "incident": {
        "incidentId": "inc_prod_402",
        "title": "Database Connection Saturation",
        "service": "checkout-service",
        "severity": "SEV-1",
        "transcript": """[2026-10-25T07:00:00Z] System startup completed.
[ev_01] checkout-service latency p99 reached 4800ms
[ev_02] Active postgres connection pool on checkout-db: 200/200 (exhausted)
[chat_1] Bob: Hey is checkout down?
[chat_2] Alice: Investigating now, seeing pool timeout errors
[ev_03] postgres connection timeout after 30000ms on checkout-db
[ev_04] CPU utilization is 35% on checkout-service
[chat_3] Bob: Customer reported error: "Unable to complete order"
[info_01] Canary version v3.1.2 was deployed 3 days ago with no issues""",
        "allowedRootCauses": [
            "database_connection_pool_exhaustion",
            "cpu_saturation",
            "canary_deployment_regression"
        ]
    },
    "toolCatalog": [
        {
            "name": "check_db_pool",
            "description": "Inspect connection pool statistics for a target database",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "database": {"type": "string", "description": "Database identifier"},
                    "service": {"type": "string", "description": "Service name"}
                },
                "required": ["database", "service"]
            }
        },
        {
            "name": "query_cpu_metrics",
            "description": "Query CPU usage for service",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "service": {"type": "string"}
                },
                "required": ["service"]
            }
        },
        {
            "name": "scale_service",
            "description": "Scale service replicas",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "service": {"type": "string"},
                    "replicas": {"type": "integer"}
                },
                "required": ["service"]
            }
        },
        {
            "name": "rollback_deployment",
            "description": "Rollback a deployment",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "service": {"type": "string"}
                },
                "required": ["service"]
            }
        }
    ],
    "policy": {
        "maximumDiagnostics": 3,
        "effectTools": ["scale_service", "rollback_deployment"],
        "approvalRequiredFor": ["rollback_deployment"],
        "doNotExport": ["accessToken"]
    }
}

t0 = time.time()
req = urllib.request.Request(
    "https://ga5-incident-agent-z8w6.onrender.com/v2/incidents",
    data=json.dumps(test_incident).encode(),
    headers={"Content-Type": "application/json"}
)

try:
    with urllib.request.urlopen(req, timeout=18) as res:
        elapsed = round(time.time() - t0, 3)
        print(f"POST /v2/incidents responded in {elapsed}s with status {res.status}")
        data = json.loads(res.read().decode())
        print("Response JSON:")
        print(json.dumps(data, indent=2))
except urllib.error.HTTPError as e:
    print(f"HTTP ERROR {e.code}: {e.read().decode()}")
except Exception as e:
    print(f"ERROR: {e}")
