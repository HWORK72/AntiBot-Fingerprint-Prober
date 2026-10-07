from network.tls_parser import TLSFingerprint
from network.h2_parser import H2Fingerprint
from network.tcp_analyzer import TCPMetrics
from client_probes.schemas import ClientProbePayload
from client_probes.cdp_detector import CDPAnalyzer, CDPVerdict
from client_probes.hardware_probe import HardwareAnalyzer, HardwareVerdict
from client_probes.environment_probe import EnvironmentAnalyzer, EnvironmentVerdict
from scoring.rules import PENALTY_REGISTRY, RiskSeverity, PenaltyRule
from scoring.advisor import RemediationAdvisor
from scoring.schemas import StealthAssessment, DetectedAnomaly


class ScoringEngine:

    @classmethod
    def evaluate(
        cls,
        tls: TLSFingerprint | None,
        h2: H2Fingerprint | None,
        tcp: TCPMetrics | None,
        client: ClientProbePayload | None,
        claimed_user_agent: str
    ) -> StealthAssessment:
        applied_rules: list[PenaltyRule] = []

        ua_is_chrome: bool = "chrome" in claimed_user_agent.lower() and "edg" not in claimed_user_agent.lower()

        if tls:
            if ua_is_chrome and not tls.is_grease_present:
                applied_rules.append(PENALTY_REGISTRY["TLS_GREASE_ABSENT_CHROME"])

        if h2:
            if ua_is_chrome and h2.pseudo_headers_order:
                expected_chrome_order: list[str] = [":method", ":authority", ":scheme", ":path"]
                if h2.pseudo_headers_order != expected_chrome_order:
                    applied_rules.append(PENALTY_REGISTRY["H2_PSEUDO_ORDER_ANOMALY"])

        if tcp:
            if tcp.is_os_mismatch:
                applied_rules.append(PENALTY_REGISTRY["TCP_OS_MISMATCH"])

        if client:
            cdp_res: CDPVerdict = CDPAnalyzer.inspect(client.cdp_check)
            if client.cdp_check.runtime_enable_leaks:
                applied_rules.append(PENALTY_REGISTRY["CDP_RUNTIME_ENABLE"])
            if client.cdp_check.cdc_markers_found:
                applied_rules.append(PENALTY_REGISTRY["CDP_CDC_MARKERS"])
            if client.cdp_check.native_fn_tampered:
                applied_rules.append(PENALTY_REGISTRY["NATIVE_FN_TAMPERED"])

            hw_res: HardwareVerdict = HardwareAnalyzer.inspect(client.webgl, client.audio, client.canvas)
            if hw_res.is_virtual_hardware:
                applied_rules.append(PENALTY_REGISTRY["VIRTUAL_GPU_SWIFTSHADER"])
            if hw_res.is_canvas_manipulated:
                applied_rules.append(PENALTY_REGISTRY["CANVAS_POISONING"])

            env_res: EnvironmentVerdict = EnvironmentAnalyzer.inspect(
                client.webdriver_flag,
                client.plugins_length,
                client.worker_check
            )
            if client.webdriver_flag:
                applied_rules.append(PENALTY_REGISTRY["WEBDRIVER_ACTIVE"])
            if client.plugins_length == 0:
                applied_rules.append(PENALTY_REGISTRY["ZERO_PLUGINS"])
            if not client.worker_check.user_agent_match:
                applied_rules.append(PENALTY_REGISTRY["WORKER_UA_MISMATCH"])

        total_penalty: int = 0
        has_critical: bool = False
        critical_count: int = 0
        anomalies_list: list[DetectedAnomaly] = []

        seen_rule_ids: set[str] = set()

        for rule in applied_rules:
            if rule.rule_id in seen_rule_ids:
                continue
            seen_rule_ids.add(rule.rule_id)

            total_penalty += rule.penalty_score
            if rule.severity == RiskSeverity.CRITICAL:
                has_critical = True
                critical_count += 1

            anomalies_list.append(
                DetectedAnomaly(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    penalty=rule.penalty_score,
                    title=rule.title,
                    description=rule.description,
                    recommendation=RemediationAdvisor.get_advice(rule.rule_id)
                )
            )

        raw_score: int = 100 - total_penalty
        stealth_score: int = max(0, min(100, raw_score))

        if has_critical:
            stealth_score = min(stealth_score, 10)

        if stealth_score >= 85:
            status_verdict: str = "UNDETECTED (Optimal Masking)"
        elif stealth_score >= 50:
            status_verdict: str = "SUSPICIOUS (High Anomaly Risk)"
        else:
            status_verdict: str = "BUSTED (Immediate Flag / High Risk)"

        return StealthAssessment(
            stealth_score=stealth_score,
            status=status_verdict,
            total_penalties=total_penalty,
            critical_triggers_count=critical_count,
            anomalies=anomalies_list
        )