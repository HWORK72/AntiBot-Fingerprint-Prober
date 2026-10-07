from pydantic import BaseModel, Field
from client_probes.schemas import CDPReport


class CDPVerdict(BaseModel):
    is_bot_detected: bool = Field(default=False)
    critical_anomalies: list[str] = Field(default_factory=list)


class CDPAnalyzer:

    @staticmethod
    def inspect(report: CDPReport) -> CDPVerdict:
        anomalies: list[str] = []

        if report.runtime_enable_leaks:
            anomalies.append("Captured CDP 'Runtime.enable' call side-effects in V8 inspector")

        if report.cdc_markers_found:
            markers_str: str = ", ".join(report.cdc_markers_found)
            anomalies.append(f"ChromeDriver / Selenium element cache properties detected: [{markers_str}]")

        if report.stack_trace_anomaly:
            anomalies.append("V8 Error.prepareStackTrace call-stack generation anomaly detected")

        if report.native_fn_tampered:
            anomalies.append("Function.prototype.toString tampering detected (hooked native API)")

        return CDPVerdict(
            is_bot_detected=len(anomalies) > 0,
            critical_anomalies=anomalies
        )