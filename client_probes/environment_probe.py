from pydantic import BaseModel, Field
from client_probes.schemas import WorkerConsistencyReport


class EnvironmentVerdict(BaseModel):
    is_inconsistent: bool = Field(default=False)
    anomalies: list[str] = Field(default_factory=list)


class EnvironmentAnalyzer:

    @staticmethod
    def inspect(
        webdriver_flag: bool,
        plugins_length: int,
        worker_report: WorkerConsistencyReport
    ) -> EnvironmentVerdict:
        anomalies: list[str] = []

        if webdriver_flag:
            anomalies.append("Critical automation marker: navigator.webdriver is set to true")

        if plugins_length == 0:
            anomalies.append("navigator.plugins array is empty (typical of raw Chromium / Headless)")

        if worker_report.worker_supported:
            if not worker_report.user_agent_match:
                anomalies.append(f"Context drift: Window User-Agent differs from WebWorker ('{worker_report.worker_user_agent}')")

            if not worker_report.hardware_concurrency_match:
                anomalies.append(f"Context drift: Window hardwareConcurrency differs from WebWorker ({worker_report.worker_concurrency})")

            if not worker_report.languages_match:
                anomalies.append(f"Context drift: Window languages locale differs from WebWorker: {worker_report.worker_languages}")

        return EnvironmentVerdict(
            is_inconsistent=len(anomalies) > 0,
            anomalies=anomalies
        )