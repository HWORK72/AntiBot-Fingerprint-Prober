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
        title="Флаг автоматизации navigator.webdriver",
        description="В объекте navigator флаг webdriver установлен в true. Прямое указание на Selenium/Playwright/Puppeteer."
    ),
    "CDP_RUNTIME_ENABLE": PenaltyRule(
        rule_id="CDP_RUNTIME_ENABLE",
        severity=RiskSeverity.CRITICAL,
        penalty_score=100,
        title="Утечка Chrome DevTools Protocol (Runtime.enable)",
        description="Перехвачены сайд-эффекты инспектора CDP в консоли и стеке вызовов V8."
    ),
    "CDP_CDC_MARKERS": PenaltyRule(
        rule_id="CDP_CDC_MARKERS",
        severity=RiskSeverity.CRITICAL,
        penalty_score=100,
        title="Маркеры автоматизации ChromeDriver (cdc_*)",
        description="В объекте window обнаружены скрытые переменные кеша элементов ChromeDriver."
    ),
    "VIRTUAL_GPU_SWIFTSHADER": PenaltyRule(
        rule_id="VIRTUAL_GPU_SWIFTSHADER",
        severity=RiskSeverity.CRITICAL,
        penalty_score=90,
        title="Программная виртуализация GPU (SwiftShader/llvmpipe)",
        description="WebGL запущен на софтверном рендерере без дискретной или интегрированной видеокарты (характерно для серверов)."
    ),
    "TLS_GREASE_ABSENT_CHROME": PenaltyRule(
        rule_id="TLS_GREASE_ABSENT_CHROME",
        severity=RiskSeverity.HIGH,
        penalty_score=60,
        title="Отсутствие GREASE шифров для Chrome",
        description="User-Agent заявляет Google Chrome, но в пакете TLS Client Hello отсутствуют псевдо-шифры RFC 8701."
    ),
    "H2_PSEUDO_ORDER_ANOMALY": PenaltyRule(
        rule_id="H2_PSEUDO_ORDER_ANOMALY",
        severity=RiskSeverity.HIGH,
        penalty_score=60,
        title="Аномальный порядок псевдо-заголовков HTTP/2",
        description="Chrome отправляет псевдо-заголовки строго в порядке :method,:authority,:scheme,:path. Нарушение выдает питоновский стек (h2/httpx)."
    ),
    "WORKER_UA_MISMATCH": PenaltyRule(
        rule_id="WORKER_UA_MISMATCH",
        severity=RiskSeverity.HIGH,
        penalty_score=50,
        title="Конфликт User-Agent между Window и WebWorker",
        description="Подмена User-Agent была сделана только на уровне window, изолированный фоновый поток WebWorker выдал реальную систему."
    ),
    "NATIVE_FN_TAMPERED": PenaltyRule(
        rule_id="NATIVE_FN_TAMPERED",
        severity=RiskSeverity.HIGH,
        penalty_score=40,
        title="Модификация Function.prototype.toString",
        description="Обнаружена некорректная попытка скрыть проксирование нативных браузерных методов."
    ),
    "TCP_OS_MISMATCH": PenaltyRule(
        rule_id="TCP_OS_MISMATCH",
        severity=RiskSeverity.MEDIUM,
        penalty_score=35,
        title="Несоответствие ядра ОС и сетевого стека TCP/IP",
        description="User-Agent заявляет Windows (ожидается TTL=128), но сетевой стек пакета соответствует Linux (TTL=64)."
    ),
    "CANVAS_POISONING": PenaltyRule(
        rule_id="CANVAS_POISONING",
        severity=RiskSeverity.MEDIUM,
        penalty_score=30,
        title="Искусственный шум в Canvas",
        description="Зафиксирована рандомизация отпечатка Canvas. Антифрод-системы детектируют нестабильность повторных хэшей."
    ),
    "ZERO_PLUGINS": PenaltyRule(
        rule_id="ZERO_PLUGINS",
        severity=RiskSeverity.LOW,
        penalty_score=15,
        title="Пустой список плагинов navigator.plugins",
        description="В обычном настольном браузере всегда присутствуют базовые PDF-вьюеры."
    ),
}