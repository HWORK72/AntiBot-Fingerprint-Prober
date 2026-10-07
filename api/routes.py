from pathlib import Path
from fastapi import APIRouter, BackgroundTasks, Request, WebSocket
from fastapi.responses import HTMLResponse
from core.config import settings
from client_probes.js_scripts import PROBE_JS_SCRIPT
from client_probes.schemas import ClientProbePayload
from scoring.engine import ScoringEngine, StealthAssessment
from api.schemas import FastInspectResponse, HealthResponse, ProbeRequest
from api.websocket import WebSocketManager
from ui.terminal_view import TerminalPresenter
from network.tls_parser import TLSFingerprint
from storage.redis_client import state_broker
from storage.repository import ScanResultRepository

router: APIRouter = APIRouter()

TEMPLATES_DIR: Path = Path(__file__).resolve().parent.parent / "ui" / "templates"


@router.get("/", response_class=HTMLResponse)
async def serve_dashboard() -> HTMLResponse:
    index_file: Path = TEMPLATES_DIR / "index.html"
    raw_html: str = index_file.read_text(encoding="utf-8")
    rendered_html: str = raw_html.replace("{{ js_script | safe }}", PROBE_JS_SCRIPT)
    return HTMLResponse(content=rendered_html)


@router.post("/api/v1/probe", response_model=StealthAssessment)
async def submit_probe(
    request: Request,
    body: ProbeRequest,
    background_tasks: BackgroundTasks
) -> StealthAssessment:
    client_ip: str = request.client.host if request.client else "127.0.0.1"
    ua: str = body.client_payload.user_agent
    tls_info: TLSFingerprint | None = await state_broker.get_tls_fingerprint(client_ip)

    assessment: StealthAssessment = ScoringEngine.evaluate(
        tls=tls_info,
        h2=None,
        tcp=None,
        client=body.client_payload,
        claimed_user_agent=ua
    )

    TerminalPresenter.render_assessment(
        assessment=assessment,
        user_agent=ua,
        client_ip=client_ip,
        tls=tls_info
    )

    background_tasks.add_task(
        ScanResultRepository.persist_scan,
        client_ip=client_ip,
        user_agent=ua,
        assessment=assessment,
        ja3=tls_info.ja3 if tls_info else None,
        ja4=tls_info.ja4 if tls_info else None
    )

    return assessment


@router.get("/api/v1/inspect", response_model=FastInspectResponse)
async def inspect_fast(
    request: Request,
    background_tasks: BackgroundTasks
) -> FastInspectResponse:
    client_ip: str = request.client.host if request.client else "127.0.0.1"
    headers_dict: dict[str, str] = dict(request.headers)
    ua: str = headers_dict.get("user-agent", "Unknown")
    tls_info: TLSFingerprint | None = await state_broker.get_tls_fingerprint(client_ip)

    assessment: StealthAssessment = ScoringEngine.evaluate(
        tls=tls_info,
        h2=None,
        tcp=None,
        client=None,
        claimed_user_agent=ua
    )

    TerminalPresenter.render_assessment(
        assessment=assessment,
        user_agent=ua,
        client_ip=client_ip,
        tls=tls_info
    )

    background_tasks.add_task(
        ScanResultRepository.persist_scan,
        client_ip=client_ip,
        user_agent=ua,
        assessment=assessment,
        ja3=tls_info.ja3 if tls_info else None,
        ja4=tls_info.ja4 if tls_info else None
    )

    return FastInspectResponse(
        client_ip=client_ip,
        user_agent=ua,
        headers=headers_dict,
        stealth_assessment=assessment
    )


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    return HealthResponse(
        status="healthy",
        app_name=settings.app_name
    )


@router.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await WebSocketManager.handle_prober_connection(websocket)