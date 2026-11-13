import argparse
import asyncio
import sys
import uvicorn
from fastapi import FastAPI
from core.config import settings
from core.logger import logger
from api import router
from benchmark.runner import BotBenchmarkRunner
from network.cert_gen import ensure_ssl_certificates
from network.tls_sniffer import TLSSnifferProxy
from storage import db_manager, state_broker


def create_application() -> FastAPI:
    application: FastAPI = FastAPI(
        title=settings.app_name,
        docs_url="/docs" if settings.debug else None,
        redoc_url=None
    )
    application.include_router(router)
    return application


app: FastAPI = create_application()


async def _run_integrated_benchmark(
    http_server: uvicorn.Server,
    https_server: uvicorn.Server,
    sniffer: TLSSnifferProxy
) -> None:
    runner: BotBenchmarkRunner = BotBenchmarkRunner()
    for _ in range(40):
        if await runner.check_server_readiness():
            break
        await asyncio.sleep(0.25)
    await runner.execute_all()
    http_server.should_exit = True
    https_server.should_exit = True
    await sniffer.stop()


async def start_dual_stack(run_benchmark: bool = False) -> int:
    exit_code: int = 0
    sniffer: TLSSnifferProxy | None = None

    try:
        db_manager.initialize()
        await db_manager.create_tables()
        await state_broker.connect()

        cert_path, key_path = ensure_ssl_certificates()

        sniffer = TLSSnifferProxy(
            listen_host=settings.server_host,
            listen_port=settings.tls_prober_port,
            target_port=settings.internal_tls_port
        )
        await sniffer.start()

        http_config: uvicorn.Config = uvicorn.Config(
            app=app,
            host=settings.server_host,
            port=settings.http_port,
            log_level=settings.log_level.lower(),
            access_log=False
        )
        http_server: uvicorn.Server = uvicorn.Server(http_config)

        https_config: uvicorn.Config = uvicorn.Config(
            app=app,
            host=settings.server_host,
            port=settings.internal_tls_port,
            ssl_certfile=str(cert_path),
            ssl_keyfile=str(key_path),
            log_level=settings.log_level.lower(),
            access_log=False
        )
        https_server: uvicorn.Server = uvicorn.Server(https_config)

        logger.info(f"Web Dashboard (HTTP): http://{settings.server_host}:{settings.http_port}")
        logger.info(f"TLS Prober Gate (HTTPS): https://{settings.server_host}:{settings.tls_prober_port}")
        logger.info("System operational across all layers (L4-L7 + Lua + JS Runtime + Storage).")

        if run_benchmark:
            await asyncio.gather(
                http_server.serve(),
                https_server.serve(),
                _run_integrated_benchmark(http_server, https_server, sniffer)
            )
        else:
            await asyncio.gather(
                http_server.serve(),
                https_server.serve()
            )

    except asyncio.CancelledError:
        logger.info("Server tasks cancelled cleanly.")
    except Exception as exc:
        logger.critical(f"Fatal service initialization failure: {exc}", exc_info=True)
        exit_code = 1
    finally:
        if sniffer is not None:
            await sniffer.stop()
        await state_broker.close()
        await db_manager.close()

    return exit_code


def parse_args() -> argparse.Namespace:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(description="AntiBot-Fingerprint-Prober")
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Start dual-stack server, run integrated stealth benchmark, and exit"
    )
    return parser.parse_args()


def main_entry() -> None:
    args: argparse.Namespace = parse_args()
    exit_code: int = 0
    try:
        exit_code = asyncio.run(start_dual_stack(run_benchmark=args.benchmark))
    except KeyboardInterrupt:
        logger.info("Server gracefully terminated by user.")
    sys.exit(exit_code)


if __name__ == "__main__":
    main_entry()