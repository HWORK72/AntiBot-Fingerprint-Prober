import json
import redis.asyncio as aioredis
from core.config import settings
from core.logger import logger
from network.tls_parser import TLSFingerprint


class EphemeralStateBroker:

    def __init__(self) -> None:
        self.redis_client: aioredis.Redis | None = None
        self.is_connected: bool = False
        self._fallback_cache: dict[str, str] = {}

    async def connect(self) -> None:
        try:
            self.redis_client = aioredis.from_url(
                settings.redis_url,
                encoding="utf-8",
                decode_responses=True,
                socket_connect_timeout=2
            )
            await self.redis_client.ping()
            self.is_connected = True
            logger.info(f"Connected to Redis broker at {settings.redis_host}:{settings.redis_port}")
        except Exception as exc:
            logger.warning(f"Redis host unreachable ({exc}). Falling back to local in-memory buffer.")
            self.is_connected = False
            self.redis_client = None

    async def store_tls_fingerprint(self, client_ip: str, fingerprint: TLSFingerprint, ttl_seconds: int = 30) -> None:
        serialized: str = fingerprint.model_dump_json()
        key: str = f"tls_fp:{client_ip}"

        if self.is_connected and self.redis_client:
            try:
                await self.redis_client.set(key, serialized, ex=ttl_seconds)
                return
            except Exception as exc:
                logger.error(f"Redis write error: {exc}")

        self._fallback_cache[key] = serialized

    async def get_tls_fingerprint(self, client_ip: str) -> TLSFingerprint | None:
        key: str = f"tls_fp:{client_ip}"
        raw_json: str | None = None

        if self.is_connected and self.redis_client:
            try:
                raw_json = await self.redis_client.get(key)
            except Exception as exc:
                logger.error(f"Redis read error: {exc}")

        if not raw_json:
            raw_json = self._fallback_cache.get(key)

        if not raw_json:
            return None

        try:
            data = json.loads(raw_json)
            return TLSFingerprint.model_validate(data)
        except Exception as exc:
            logger.error(f"TLS fingerprint deserialization error: {exc}")
            return None

    async def close(self) -> None:
        if self.redis_client:
            await self.redis_client.close()
            logger.info("Redis broker connection cleanly closed.")


state_broker: EphemeralStateBroker = EphemeralStateBroker()