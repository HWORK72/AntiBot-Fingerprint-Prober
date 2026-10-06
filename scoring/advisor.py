from scoring.rules import RiskSeverity


class RemediationAdvisor:

    @staticmethod
    def get_advice(rule_id: str) -> str:
        advice_map: dict[str, str] = {
            "WEBDRIVER_ACTIVE": (
                "Запустите Chromium с аргументом '--disable-blink-features=AutomationControlled' "
                "или используйте библиотеку stealth для очистки флага."
            ),
            "CDP_RUNTIME_ENABLE": (
                "Используйте изолированный ExecutionContext для инъекций или пропатчите CDP-транспорт, "
                "чтобы события Runtime.enable не триггерили инспекцию стека вызовов в V8."
            ),
            "CDP_CDC_MARKERS": (
                "Откройте бинарник chromedriver в hex-редакторе и замените подстроку 'cdc_' "
                "на случайные символы равной длины, либо перейдите на Playwright с кастомным CDP."
            ),
            "VIRTUAL_GPU_SWIFTSHADER": (
                "Запускайте браузер на хосте с реальной видеокартой или пробросьте GPU флаги: "
                "'--use-gl=angle', '--use-angle=default'. На Linux настройте виртуальный X-сервер (Xvfb) с аппаратным ускорением."
            ),
            "TLS_GREASE_ABSENT_CHROME": (
                "Используйте curl_cffi с параметром impersonate='chrome124' вместо requests/httpx "
                "для полной эмуляции TLS Client Hello с добавлением GREASE и правильного набора шифров."
            ),
            "H2_PSEUDO_ORDER_ANOMALY": (
                "При прямых HTTP/2 запросах зафиксируйте порядок псевдо-заголовков strictly как ':method', ':authority', ':scheme', ':path'. "
                "В curl_cffi это поведение уже реализовано в движке curl-impersonate."
            ),
            "WORKER_UA_MISMATCH": (
                "Внедрите перехват конструктора 'window.Worker' через Proxy, чтобы передавать "
                "подмененный User-Agent и параметры оборудования внутрь фонового потока."
            ),
            "NATIVE_FN_TAMPERED": (
                "Не используйте кустарные заглушки для нативных функций. Используйте Proxy с корректным "
                "переопределением дескрипторов и нативным выводом toString."
            ),
            "TCP_OS_MISMATCH": (
                "Если бот запущен на сервере Linux, измените дефолтный TTL пакетов командой: "
                "'sudo sysctl -w net.ipv4.ip_default_ttl=128', чтобы ядро отправляло пакеты как Windows."
            ),
            "CANVAS_POISONING": (
                "Отключите плагины псевдо-рандомизации Canvas (Fingerprint Defender и аналоги). "
                "Статический отпечаток конкретного железа всегда безопаснее, чем шум с плавающим хэшем."
            ),
            "ZERO_PLUGINS": (
                "Сэмулируйте объект navigator.plugins и mimeTypes в соответствии со спецификацией Chrome PDF Viewer."
            ),
        }

        return advice_map.get(rule_id, "Изучите документацию антифрод-системы для устранения данной аномалии.")