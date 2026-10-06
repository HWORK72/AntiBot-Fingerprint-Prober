from pydantic import BaseModel, Field
from core.logger import logger


class TCPMetrics(BaseModel):
    observed_ttl: int = Field(description="Observed IP packet TTL")
    estimated_initial_ttl: int = Field(description="Estimated initial TTL at sender")
    hops_count: int = Field(description="Estimated network hops")
    detected_os: str = Field(description="Inferred OS family from network stack")
    is_os_mismatch: bool = Field(default=False)
    mismatch_details: str | None = Field(default=None)


class TCPOpticalAnalyzer:

    @staticmethod
    def estimate_initial_ttl(observed_ttl: int) -> int:
        if observed_ttl <= 64:
            return 64
        elif observed_ttl <= 128:
            return 128
        else:
            return 255

    @classmethod
    def analyze(cls, observed_ttl: int, user_agent: str) -> TCPMetrics:
        try:
            initial_ttl: int = cls.estimate_initial_ttl(observed_ttl)
            hops: int = initial_ttl - observed_ttl

            if initial_ttl == 64:
                detected_os: str = "Linux/macOS/Android"
            elif initial_ttl == 128:
                detected_os: str = "Windows"
            else:
                detected_os: str = "Solaris/Cisco/Unknown"

            ua_lower: str = user_agent.lower()
            claimed_os: str | None = None

            if "windows" in ua_lower:
                claimed_os = "Windows"
            elif "macintosh" in ua_lower or "mac os" in ua_lower:
                claimed_os = "macOS"
            elif "android" in ua_lower:
                claimed_os = "Android"
            elif "linux" in ua_lower:
                claimed_os = "Linux"

            is_mismatch: bool = False
            details: str | None = None

            if claimed_os == "Windows" and initial_ttl == 64:
                is_mismatch = True
                details = f"Аномалия TCP/IP: User-Agent заявляет Windows, но сетевой стек ядра Linux (Initial TTL=64, Observed TTL={observed_ttl})"
            elif claimed_os in ("Linux", "macOS", "Android") and initial_ttl == 128:
                is_mismatch = True
                details = f"Аномалия TCP/IP: User-Agent заявляет {claimed_os}, но сетевой стек ядра Windows (Initial TTL=128, Observed TTL={observed_ttl})"

            return TCPMetrics(
                observed_ttl=observed_ttl,
                estimated_initial_ttl=initial_ttl,
                hops_count=hops,
                detected_os=detected_os,
                is_os_mismatch=is_mismatch,
                mismatch_details=details
            )

        except Exception as exc:
            logger.error(f"Ошибка пассивного анализа TCP TTL: {exc}", exc_info=True)
            return TCPMetrics(
                observed_ttl=observed_ttl,
                estimated_initial_ttl=observed_ttl,
                hops_count=0,
                detected_os="Unknown",
                is_os_mismatch=False,
                mismatch_details=None
            )