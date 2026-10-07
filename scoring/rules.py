from enum import Enum
from pydantic import BaseModel, Field


class RiskSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class PenaltyRule(BaseModel):
    rule_id: str
    severity: RiskSeverity
    penalty_score: int
    title: str
    description: str


PENALTY_REGISTRY: dict[str, PenaltyRule] = {
    "WEBDRIVER_ACTIVE": PenaltyRule(
        rule_id="WEBDRIVER_ACTIVE",
        severity=RiskSeverity.CRITICAL,
        penalty_score=100,
        title="Active 'navigator.webdriver' Automation Flag",
        description="navigator.webdriver is set to true. Unambiguous marker of Selenium, Playwright, or Puppeteer."
    ),
    "CDP_RUNTIME_ENABLE": PenaltyRule(
        rule_id="CDP_RUNTIME_ENABLE",
        severity=RiskSeverity.CRITICAL,
        penalty_score=100,
        title="CDP 'Runtime.enable' Protocol Leakage",
        description="Captured DevTools inspector side-effects in console logging and V8 execution call stacks."
    ),
    "CDP_CDC_MARKERS": PenaltyRule(
        rule_id="CDP_CDC_MARKERS",
        severity=RiskSeverity.CRITICAL,
        penalty_score=100,
        title="ChromeDriver Automation Cache Artifacts (cdc_*)",
        description="Global window object contains internal element cache properties matching ChromeDriver signatures."
    ),
    "VIRTUAL_GPU_SWIFTSHADER": PenaltyRule(
        rule_id="VIRTUAL_GPU_SWIFTSHADER",
        severity=RiskSeverity.CRITICAL,
        penalty_score=90,
        title="Software GPU Virtualization (SwiftShader/llvmpipe)",
        description="WebGL is executing on CPU software rasterizers without physical or discrete graphics hardware."
    ),
    "TLS_GREASE_ABSENT_CHROME": PenaltyRule(
        rule_id="TLS_GREASE_ABSENT_CHROME",
        severity=RiskSeverity.HIGH,
        penalty_score=60,
        title="Missing RFC 8701 GREASE Ciphers for Chrome UA",
        description="User-Agent claims Google Chrome, but TLS Client Hello lacks required GREASE ciphers and extensions."
    ),
    "H2_PSEUDO_ORDER_ANOMALY": PenaltyRule(
        rule_id="H2_PSEUDO_ORDER_ANOMALY",
        severity=RiskSeverity.HIGH,
        penalty_score=60,
        title="Non-Standard HTTP/2 Pseudo-Header Sequence",
        description="Chrome strictly transmits :method, :authority, :scheme, :path. Deviation reveals Python h2/httpx stack."
    ),
    "WORKER_UA_MISMATCH": PenaltyRule(
        rule_id="WORKER_UA_MISMATCH",
        severity=RiskSeverity.HIGH,
        penalty_score=50,
        title="Execution Context Drift (Window vs WebWorker UA)",
        description="User-Agent spoofing was applied strictly to the window context; isolated WebWorker revealed host OS."
    ),
    "NATIVE_FN_TAMPERED": PenaltyRule(
        rule_id="NATIVE_FN_TAMPERED",
        severity=RiskSeverity.HIGH,
        penalty_score=40,
        title="Function.prototype.toString Tampering Detected",
        description="Detected improper proxy trap or polyfill hiding hooked browser native methods."
    ),
    "TCP_OS_MISMATCH": PenaltyRule(
        rule_id="TCP_OS_MISMATCH",
        severity=RiskSeverity.MEDIUM,
        penalty_score=35,
        title="TCP/IP Network Stack vs OS Kernel Mismatch",
        description="User-Agent declares Windows (expected TTL=128), but packet initial TTL indicates Linux kernel (TTL=64)."
    ),
    "CANVAS_POISONING": PenaltyRule(
        rule_id="CANVAS_POISONING",
        severity=RiskSeverity.MEDIUM,
        penalty_score=30,
        title="Canvas Fingerprint Poisoning / Random Noise",
        description="Inconsistent canvas render hashes captured across repeated draws. Triggers anti-fraud evasion alarms."
    ),
    "ZERO_PLUGINS": PenaltyRule(
        rule_id="ZERO_PLUGINS",
        severity=RiskSeverity.LOW,
        penalty_score=15,
        title="Empty navigator.plugins Array",
        description="Modern desktop desktop browsers expose default PDF and viewer plugins. Typical of raw Headless builds."
    ),
}