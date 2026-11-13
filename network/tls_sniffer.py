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
        client_peer: tuple[str, int] | None = client_writer.get_extra_info("peername")
        client_ip: str = client_peer[0] if client_peer else "127.0.0.1"
        upstream_writer: asyncio.StreamWriter | None = None

        try:
            initial_packet: bytes = await asyncio.wait_for(client_reader.read(4096), timeout=10.0)
            if not initial_packet:
                return

            fingerprint: TLSFingerprint | None = TLSClientHelloParser.parse(initial_packet)
            if fingerprint:
                await state_broker.store_tls_fingerprint(client_ip, fingerprint)

            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(host="127.0.0.1", port=self.target_port),
                timeout=5.0
            )

            upstream_writer.write(initial_packet)
            await upstream_writer.drain()

            async def relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
                try:
                    while True:
                        chunk: bytes = await reader.read(8192)
                        if not chunk:
                            if writer.can_write_eof():
                                writer.write_eof()
                            break
                        writer.write(chunk)
                        await writer.drain()
                except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
                    pass
                except Exception as relay_exc:
                    logger.debug(f"Stream relay notice for {client_ip}: {relay_exc}")

            await asyncio.gather(
                relay(client_reader, upstream_writer),
                relay(upstream_reader, client_writer),
                return_exceptions=True
            )

        except asyncio.TimeoutError:
            logger.warning(f"TLS handshake read timeout from client {client_ip}")
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.error(f"TLS Sniffer connection error for {client_ip}: {exc}")
        finally:
            if not client_writer.is_closing():
                try:
                    client_writer.close()
                    await client_writer.wait_closed()
                except Exception:
                    pass
            if upstream_writer and not upstream_writer.is_closing():
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
        logger.info(f"TLS prober active on https://{self.listen_host}:{self.listen_port} -> Relay to :{self.target_port}")

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.server = None
            logger.info("TLS prober stopped.")