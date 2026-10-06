import asyncio
import sys
from typing import Any
from curl_cffi import requests as cffi_requests
from playwright.async_api import async_playwright, Browser, Page
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from core.config import settings
from core.logger import logger

console: Console = Console()


class BotBenchmarkRunner:

    def __init__(self) -> None:
        self.http_base_url: str = f"http://{settings.server_host}:{settings.http_port}"
        self.https_base_url: str = f"https://{settings.server_host}:{settings.tls_prober_port}"
        self.results: list[dict[str, Any]] = []

    async def check_server_readiness(self) -> bool:
        try:
            resp = cffi_requests.get(f"{self.http_base_url}/health", timeout=3)
            return resp.status_code == 200
        except Exception:
            return False

    async def run_curl_cffi_test(self, impersonate_target: str | None, test_name: str) -> None:
        try:
            headers: dict[str, str] = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
            }

            if impersonate_target:
                resp = cffi_requests.get(
                    f"{self.https_base_url}/api/v1/inspect",
                    headers=headers,
                    impersonate=impersonate_target,
                    verify=False,
                    timeout=5
                )
            else:
                resp = cffi_requests.get(
                    f"{self.https_base_url}/api/v1/inspect",
                    headers=headers,
                    verify=False,
                    timeout=5
                )

            data: dict[str, Any] = resp.json()
            assessment: dict[str, Any] = data.get("stealth_assessment", {})

            self.results.append({
                "bot_name": test_name,
                "type": "Network (TLS/JA4)",
                "score": assessment.get("stealth_score", 0),
                "status": assessment.get("status", "UNKNOWN"),
                "critical": assessment.get("critical_triggers_count", 0),
                "anomalies_count": len(assessment.get("anomalies", []))
            })

        except Exception as exc:
            logger.error(f"Сбой при выполнении теста {test_name}: {exc}", exc_info=True)
            self.results.append({
                "bot_name": test_name,
                "type": "Network (TLS/JA4)",
                "score": 0,
                "status": "CRASHED",
                "critical": 1,
                "anomalies_count": 1
            })

    async def run_playwright_test(self, stealth_mode: bool, test_name: str) -> None:
        try:
            async with async_playwright() as pw:
                launch_args: list[str] = [
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                ]

                if stealth_mode:
                    launch_args.extend([
                        "--disable-blink-features=AutomationControlled",
                        "--use-gl=angle",
                        "--use-angle=default",
                    ])

                browser: Browser = await pw.chromium.launch(
                    headless=True,
                    args=launch_args
                )

                context_kwargs: dict[str, Any] = {
                    "viewport": {"width": 1920, "height": 1080},
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                    "locale": "en-US",
                    "timezone_id": "America/New_York",
                }

                context = await browser.new_context(**context_kwargs)
                page: Page = await context.new_page()

                if stealth_mode:
                    await page.add_init_script("""
                        Object.defineProperty(navigator, 'webdriver', {
                            get: () => undefined
                        });
                        Object.defineProperty(navigator, 'plugins', {
                            get: () => [1, 2, 3, 4, 5]
                        });
                    """)

                await page.goto(self.http_base_url, wait_until="networkidle", timeout=10000)
                await page.wait_for_selector("#score-display:not(:empty)", timeout=6000)

                score_text: str = await page.inner_text("#score-display")
                verdict_text: str = await page.inner_text("#verdict-display")
                crit_text: str = await page.inner_text("#crit-count")

                score_cleaned: int = int(score_text.replace("%", "").strip()) if score_text.replace("%", "").strip().isdigit() else 0
                crit_cleaned: int = int(crit_text.strip()) if crit_text.strip().isdigit() else 0

                await browser.close()

                self.results.append({
                    "bot_name": test_name,
                    "type": "Browser (JS Runtime)",
                    "score": score_cleaned,
                    "status": verdict_text,
                    "critical": crit_cleaned,
                    "anomalies_count": crit_cleaned
                })

        except Exception as exc:
            logger.error(f"Сбой при выполнении теста {test_name}: {exc}", exc_info=True)
            self.results.append({
                "bot_name": test_name,
                "type": "Browser (JS Runtime)",
                "score": 0,
                "status": "CRASHED",
                "critical": 1,
                "anomalies_count": 1
            })

    def render_benchmark_summary(self) -> None:
        console.print()
        console.print(Panel("[bold cyan]РЕЗУЛЬТАТЫ СРАВНИТЕЛЬНОГО БЕНЧМАРКА АНТИДЕТЕКТ-МАСКИРОВКИ[/bold cyan]", border_style="cyan"))

        table: Table = Table(
            title="Сводная диагностическая таблица ботов",
            header_style="bold magenta",
            show_lines=True
        )

        table.add_column("Бот / Стек Клиента", style="white", width=30)
        table.add_column("Уровень Проверки", style="cyan", width=24)
        table.add_column("Stealth Score", justify="center", width=14)
        table.add_column("Критических Детектов", justify="center", width=16)
        table.add_column("Вердикт Антифрода", style="bold", width=32)

        for res in self.results:
            score: int = res["score"]
            if score >= 85:
                score_str: str = f"[bold green]{score}%[/bold green]"
                status_str: str = f"[green]{res['status']}[/green]"
            elif score >= 50:
                score_str: str = f"[bold yellow]{score}%[/bold yellow]"
                status_str: str = f"[yellow]{res['status']}[/yellow]"
            else:
                score_str: str = f"[bold red]{score}%[/bold red]"
                status_str: str = f"[red]{res['status']}[/red]"

            crit_count: int = res["critical"]
            crit_str: str = f"[bold red]{crit_count}[/bold red]" if crit_count > 0 else "[green]0[/green]"

            table.add_row(
                res["bot_name"],
                res["type"],
                score_str,
                crit_str,
                status_str
            )

        console.print(table)
        console.print()

    async def execute_all(self) -> None:
        logger.info(f"Проверка доступности диагностического сервера по адресу {self.http_base_url}...")
        is_ready: bool = await self.check_server_readiness()

        if not is_ready:
            logger.critical(
                f"Диагностический сервер на {self.http_base_url} недоступен. "
                "Запустите сервер (Shift+F10 на main.py) перед стартом бенчмарка!"
            )
            return

        logger.info("[bold cyan]>>> Запуск Теста 1: Стандартный Python HTTP клиент (без маскировок)[/bold cyan]")
        await self.run_curl_cffi_test(impersonate_target=None, test_name="Python Vanilla Client")

        logger.info("[bold cyan]>>> Запуск Теста 2: curl_cffi с имперсонацией Chrome 124 (TLS/JA4 Spoofing)[/bold cyan]")
        await self.run_curl_cffi_test(impersonate_target="chrome124", test_name="curl_cffi (Chrome 124)")

        logger.info("[bold cyan]>>> Запуск Теста 3: Playwright Chromium (Стандартный Headless)[/bold cyan]")
        await self.run_playwright_test(stealth_mode=False, test_name="Playwright Vanilla Headless")

        logger.info("[bold cyan]>>> Запуск Теста 4: Playwright Chromium (Advanced Anti-Detect Patched)[/bold cyan]")
        await self.run_playwright_test(stealth_mode=True, test_name="Playwright Stealth Patched")

        self.render_benchmark_summary()


async def main() -> None:
    runner: BotBenchmarkRunner = BotBenchmarkRunner()
    await runner.execute_all()


if __name__ == "__main__":
    asyncio.run(main())