from pydantic import BaseModel, Field
from client_probes.schemas import ClientProbePayload
from scoring.engine import StealthAssessment


class ProbeRequest(BaseModel):
    client_payload: ClientProbePayload


class FastInspectResponse(BaseModel):
    client_ip: str
    user_agent: str
    headers: dict[str, str]
    stealth_assessment: StealthAssessment


class HealthResponse(BaseModel):
    status: str
    app_name: str
    version: str = "1.0.0"