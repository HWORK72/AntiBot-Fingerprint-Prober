import json
from fastapi import WebSocket, WebSocketDisconnect
from core.logger import logger
from client_probes.schemas import ClientProbePayload
from scoring.engine import ScoringEngine, StealthAssessment
from ui.terminal_view import TerminalPresenter


class WebSocketManager:

    @classmethod
    async def handle_prober_connection(cls, websocket: WebSocket) -> None:
        await websocket.accept()
        client_ip: str = websocket.client.host if websocket.client else "127.0.0.1"

        try:
            raw_data: str = await websocket.receive_text()
            data_dict: dict = json.loads(raw_data)
            client_payload: ClientProbePayload = ClientProbePayload.model_validate(data_dict)

            ua: str = client_payload.user_agent
            assessment: StealthAssessment = ScoringEngine.evaluate(
                tls=None,
                h2=None,
                tcp=None,
                client=client_payload,
                claimed_user_agent=ua
            )

            TerminalPresenter.render_assessment(
                assessment=assessment,
                user_agent=ua,
                client_ip=client_ip
            )

            await websocket.send_text(assessment.model_dump_json())

        except WebSocketDisconnect:
            logger.info(f"Клиент отключился: {client_ip}")
        except Exception as exc:
            logger.error(f"Сбой обработки WebSocket сообщения: {exc}", exc_info=True)
            try:
                await websocket.close()
            except Exception:
                pass