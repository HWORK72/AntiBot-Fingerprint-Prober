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
            anomalies.append("Обнаружена утечка вызова Runtime.enable (активный Chrome DevTools Protocol)")

        if report.cdc_markers_found:
            markers_str: str = ", ".join(report.cdc_markers_found)
            anomalies.append(f"Найдены скрытые маркеры автоматизации ChromeDriver/Selenium: [{markers_str}]")

        if report.stack_trace_anomaly:
            anomalies.append("Аномалия генерации стека вызовов Error.prepareStackTrace (признак инъекции раннера)")

        if report.native_fn_tampered:
            anomalies.append("Подделка Function.prototype.toString (попытка скрыть проксирование нативных API)")

        return CDPVerdict(
            is_bot_detected=len(anomalies) > 0,
            critical_anomalies=anomalies
        )