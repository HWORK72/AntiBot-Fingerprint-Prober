from scoring.rules import RiskSeverity


class RemediationAdvisor:

    @staticmethod
    def get_advice(rule_id: str) -> str:
        advice_map: dict[str, str] = {
            "WEBDRIVER_ACTIVE": (
                "Launch Chromium with flag '--disable-blink-features=AutomationControlled' "
                "or apply an evasion shim to patch the descriptor before DOM loading."
            ),
            "CDP_RUNTIME_ENABLE": (
                "Use isolated ExecutionContexts for evaluations or patch the CDP transport layer "
                "so Runtime.enable events do not trigger prepareStackTrace inspection hooks in V8."
            ),
            "CDP_CDC_MARKERS": (
                "Patch the ChromeDriver binary in a hex editor replacing 'cdc_' prefixes "
                "with randomized alphanumeric sequences, or transition to Playwright with custom CDP."
            ),
            "VIRTUAL_GPU_SWIFTSHADER": (
                "Execute the browser on hardware with a physical/integrated GPU, or pass: "
                "'--use-gl=angle', '--use-angle=default'. On Linux servers configure a hardware-accelerated Xvfb buffer."
            ),
            "TLS_GREASE_ABSENT_CHROME": (
                "Use curl_cffi with impersonate='chrome124' instead of requests/httpx "
                "for bit-for-bit TLS Client Hello emulation including GREASE and cipher priority lists."
            ),
            "H2_PSEUDO_ORDER_ANOMALY": (
                "Enforce strict HTTP/2 pseudo-header serialization: ':method', ':authority', ':scheme', ':path'. "
                "In curl_cffi this ordering is handled natively by the curl-impersonate backend."
            ),
            "WORKER_UA_MISMATCH": (
                "Hook 'window.Worker' constructor via Proxy to inject the overridden User-Agent "
                "and hardwareConcurrency parameters into child worker execution contexts."
            ),
            "NATIVE_FN_TAMPERED": (
                "Avoid naive prototype overrides. Use Proxy handlers with accurate descriptor definitions "
                "and native-matching Function.prototype.toString outputs."
            ),
            "TCP_OS_MISMATCH": (
                "When hosting scrapers on Linux servers pretending to be Windows, modify outbound packet TTL: "
                "'sudo sysctl -w net.ipv4.ip_default_ttl=128' to match the NT kernel network stack."
            ),
            "CANVAS_POISONING": (
                "Disable canvas noise randomizers (e.g. Fingerprint Defender extensions). "
                "A stable, consistent hardware canvas hash is significantly safer than unstable dynamic noise."
            ),
            "ZERO_PLUGINS": (
                "Mock navigator.plugins and navigator.mimeTypes arrays adhering to official Chrome PDF Viewer specs."
            ),
        }

        return advice_map.get(rule_id, "Review anti-bot diagnostic documentation to mitigate this anomaly.")