import uuid
from core.logger import logger
from scoring.schemas import StealthAssessment
from storage.db import db_manager
from storage.models import DetectedAnomalyRecord, ScanSession


class ScanResultRepository:

    @classmethod
    async def persist_scan(
        cls,
        client_ip: str,
        user_agent: str,
        assessment: StealthAssessment,
        ja3: str | None = None,
        ja4: str | None = None,
        akamai_hash: str | None = None
    ) -> uuid.UUID | None:
        if not db_manager.is_connected or not db_manager.session_factory:
            return None

        try:
            async with db_manager.session_factory() as session:
                session_record = ScanSession(
                    client_ip=client_ip,
                    user_agent=user_agent,
                    stealth_score=assessment.stealth_score,
                    verdict=assessment.status,
                    total_penalties=assessment.total_penalties,
                    critical_triggers_count=assessment.critical_triggers_count,
                    ja3_hash=ja3,
                    ja4_fingerprint=ja4,
                    akamai_hash=akamai_hash
                )
                session.add(session_record)
                await session.flush()

                for anomaly in assessment.anomalies:
                    anomaly_record = DetectedAnomalyRecord(
                        session_id=session_record.id,
                        rule_id=anomaly.rule_id,
                        severity=anomaly.severity.value,
                        penalty_score=anomaly.penalty,
                        title=anomaly.title,
                        description=anomaly.description,
                        recommendation=anomaly.recommendation
                    )
                    session.add(anomaly_record)

                await session.commit()
                return session_record.id

        except Exception as exc:
            logger.error(f"Не удалось зафиксировать отчет в базе данных: {exc}", exc_info=True)
            return None