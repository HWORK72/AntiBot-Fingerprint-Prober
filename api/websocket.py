import asyncio
import json
from typing import Any
from fastapi import WebSocket, WebSocketDisconnect
from core.logger import logger
from client_probes.schemas import ClientProbePayload
from network.tls_parser import TLSFingerprint
from scoring.engine import ScoringEngine
from scoring.schemas import StealthAssessment
from storage.redis_client import state_broker
from storage.repository import ScanResultRepository
from ui.terminal_view import TerminalPresenter

_BACKGROUND_TASKS: set[asyncio.Task[Any]] = set()


class WebSocketManager:

    @classmethod
    async def handle_prober_connection(cls, websocket: WebSocket) -> None:
        await websocket.accept()
        client_ip: str = websocket.client.host if websocket.client else "127.0.0.1"
        headers_dict: dict[str, str] = dict(websocket.headers)

        try:
            raw_data: str = await asyncio.wait_for(websocket.receive_text(), timeout=15.0)
            data_dict: dict[str, Any] = json.loads(raw_data)
            client_payload: ClientProbePayload = ClientProbePayload.model_validate(data_dict)

            ua: str = client_payload.user_agent
            tls_info: TLSFingerprint | None = await state_broker.get_tls_fingerprint(client_ip)

            assessment: StealthAssessment = ScoringEngine.evaluate(
                tls=tls_info,
                h2=None,
                tcp=None,
                client=client_payload,
                claimed_user_agent=ua,
                headers=headers_dict,
                is_websocket=True
            )

            TerminalPresenter.render_assessment(
                assessment=assessment,
                user_agent=ua,
                client_ip=client_ip,
                tls=tls_info
            )

            await websocket.send_text(assessment.model_dump_json())

            persist_task: asyncio.Task[Any] = asyncio.create_task(
                ScanResultRepository.persist_scan(
                    client_ip=client_ip,
                    user_agent=ua,
                    assessment=assessment,
                    ja3=tls_info.ja3 if tls_info else None,
                    ja4=tls_info.ja4 if tls_info else None
                )
            )
            _BACKGROUND_TASKS.add(persist_task)
            persist_task.add_done_callback(_BACKGROUND_TASKS.discard)

        except WebSocketDisconnect:
            logger.info(f"WebSocket client disconnected: {client_ip}")
        except asyncio.TimeoutError:
            logger.warning(f"WebSocket telemetry receive timeout for {client_ip}")
        except Exception as exc:
            logger.error(f"WebSocket message processing error: {exc}", exc_info=True)
            try:
                await websocket.close()
            except Exception:
                pass