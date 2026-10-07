import asyncio
import sys
import uvicorn
from fastapi import FastAPI
from core.config import settings
from core.logger import logger
from api import router
from network.cert_gen import ensure_ssl_certificates
from network.tls_sniffer import TLSSnifferProxy
from storage import db_manager, state_broker


def create_application() -> FastAPI:
    app: FastAPI = FastAPI(
        title=settings.app_name,
        docs_url="/docs" if settings.debug else None,
        redoc_url=None
    )
    app.include_router(router)
    return app


app: FastAPI = create_application()


async def start_dual_stack() -> None:
    try:
        db_manager.initialize()
        await db_manager.create_tables()
        await state_broker.connect()

        cert_path, key_path = ensure_ssl_certificates()

        internal_tls_port: int = 8444
        sniffer: TLSSnifferProxy = TLSSnifferProxy(
            listen_host=settings.server_host,
            listen_port=settings.tls_prober_port,
            target_port=internal_tls_port
        )
        await sniffer.start()

        http_config = uvicorn.Config(
            app=app,
            host=settings.server_host,
            port=settings.http_port,
            log_level=settings.log_level.lower(),
            access_log=False
        )
        http_server = uvicorn.Server(http_config)

        https_config = uvicorn.Config(
            app=app,
            host=settings.server_host,
            port=internal_tls_port,
            ssl_certfile=str(cert_path),
            ssl_keyfile=str(key_path),
            log_level=settings.log_level.lower(),
            access_log=False
        )
        https_server = uvicorn.Server(https_config)

        logger.info(f"Web Dashboard (HTTP): [bold cyan]http://{settings.server_host}:{settings.http_port}[/bold cyan]")
        logger.info(f"TLS Prober Gate (HTTPS): [bold green]https://{settings.server_host}:{settings.tls_prober_port}[/bold green]")
        logger.info("System operational across all layers (L4-L7 + JS Runtime + Storage).")

        await asyncio.gather(
            http_server.serve(),
            https_server.serve()
        )

    except Exception as exc:
        logger.critical(f"Fatal service initialization failure: {exc}", exc_info=True)
    finally:
        await state_broker.close()
        await db_manager.close()
        sys.exit(1)


def main_entry() -> None:
    try:
        asyncio.run(start_dual_stack())
    except KeyboardInterrupt:
        logger.info("Server gracefully terminated by user.")


if __name__ == "__main__":
    main_entry()