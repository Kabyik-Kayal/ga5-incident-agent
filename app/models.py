from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

class IncidentDetails(BaseModel):
    incidentId: Optional[str] = None
    title: Optional[str] = "Incident"
    service: Optional[str] = "service"
    severity: Optional[str] = "SEV-1"
    transcript: str = ""
    allowedRootCauses: List[str] = Field(default_factory=list)

class PolicyConfig(BaseModel):
    maximumDiagnostics: int = 3
    effectTools: List[str] = Field(default_factory=list)
    approvalRequiredFor: List[str] = Field(default_factory=list)
    doNotExport: List[str] = Field(default_factory=list)

class ToolDefinition(BaseModel):
    name: str
    description: Optional[str] = ""
    inputSchema: Optional[Dict[str, Any]] = Field(default_factory=dict)

class IncidentRequest(BaseModel):
    profile: str
    runId: str
    agentName: Optional[str] = "incident-response"
    publicMarker: str = "marker"
    sensitive: Optional[Dict[str, Any]] = None
    incident: IncidentDetails
    toolCatalog: List[ToolDefinition] = Field(default_factory=list)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)

class OutcomeItem(BaseModel):
    actionId: Optional[str] = None
    callId: Optional[str] = None
    attempt: int = 1
    status: int = 200
    resultClass: Optional[str] = "ok"
    nonce: Optional[str] = ""
    errorType: Optional[str] = None

class ApprovalItem(BaseModel):
    approvalId: str
    decision: str = "approved"
    nonce: str = ""

class ReceiptRequest(BaseModel):
    receiptId: str
    outcomes: Optional[List[OutcomeItem]] = None
    approvals: Optional[List[ApprovalItem]] = None

class DispatchItem(BaseModel):
    actionId: str
    callId: str
    phase: str
    toolName: str
    arguments: Dict[str, Any]
    evidence: Optional[List[str]] = None
    attempt: int = 1
    traceparent: str
    approvalId: Optional[str] = None
    approvalNonce: Optional[str] = None

class ApprovalRequestItem(BaseModel):
    approvalId: str
    actionId: str
    toolName: str
    argumentsDigest: str
