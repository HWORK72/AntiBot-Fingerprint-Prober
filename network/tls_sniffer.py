import asyncio
from core.logger import logger
from network.tls_parser import TLSClientHelloParser, TLSFingerprint
from storage.redis_client import state_broker


class TLSSnifferProxy:

    def __init__(self, listen_host: str, listen_port: int, target_port: int) -> None:
        self.listen_host: str = listen_host
        self.listen_port: int = listen_port
        self.target_port: int = target_port
        self.server: asyncio.Server | None = None

    async def _handle_connection(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter
    ) -> None:
        client_peer = client_writer.get_extra_info("peername")
        client_ip: str = client_peer[0] if client_peer else "127.0.0.1"

        upstream_writer: asyncio.StreamWriter | None = None

        try:
            initial_packet: bytes = await client_reader.read(4096)
            if not initial_packet:
                client_writer.close()
                await client_writer.wait_closed()
                return

            fingerprint: TLSFingerprint | None = TLSClientHelloParser.parse(initial_packet)
            if fingerprint:
                await state_broker.store_tls_fingerprint(client_ip, fingerprint)

            upstream_reader, upstream_writer = await asyncio.open_connection(
                host="127.0.0.1",
                port=self.target_port
            )

            upstream_writer.write(initial_packet)
            await upstream_writer.drain()

            async def relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
                try:
                    while True:
                        chunk: bytes = await reader.read(8192)
                        if not chunk:
                            break
                        writer.write(chunk)
                        await writer.drain()
                except Exception:
                    pass
                finally:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

            await asyncio.gather(
                relay(client_reader, upstream_writer),
                relay(upstream_reader, client_writer),
                return_exceptions=True
            )

        except Exception as exc:
            logger.error(f"Сбой в TLS Sniffer для клиента {client_ip}: {exc}")
        finally:
            try:
                client_writer.close()
                await client_writer.wait_closed()
            except Exception:
                pass
            if upstream_writer:
                try:
                    upstream_writer.close()
                    await upstream_writer.wait_closed()
                except Exception:
                    pass

    async def start(self) -> None:
        self.server = await asyncio.start_server(
            self._handle_connection,
            self.listen_host,
            self.listen_port
        )
        logger.info(f"TLS prober active on [bold cyan]https://{self.listen_host}:{self.listen_port}[/bold cyan] -> Relay to :{self.target_port}")

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logger.info("TLS-инспектор остановлен.")