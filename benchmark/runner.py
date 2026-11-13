import asyncio
from typing import Any
from curl_cffi.requests import AsyncSession
from playwright.async_api import async_playwright, Browser, BrowserContext, Page
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
            async with AsyncSession() as session:
                resp = await session.get(f"{self.http_base_url}/health", timeout=3)
                return resp.status_code == 200
        except Exception:
            return False

    async def run_curl_cffi_test(self, impersonate_target: str | None, test_name: str) -> None:
        try:
            if impersonate_target:
                async with AsyncSession(impersonate=impersonate_target) as session:
                    resp = await session.get(
                        f"{self.https_base_url}/api/v1/inspect",
                        verify=False,
                        timeout=5
                    )
            else:
                headers: dict[str, str] = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
                }
                async with AsyncSession() as session:
                    resp = await session.get(
                        f"{self.https_base_url}/api/v1/inspect",
                        headers=headers,
                        verify=False,
                        timeout=5
                    )

            data: dict[str, Any] = resp.json()
            assessment: dict[str, Any] = data.get("stealth_assessment", {})

            self.results.append({
                "bot_name": test_name,
                "type": "Network (TLS/JA4 + Lua L7)",
                "score": assessment.get("stealth_score", 0),
                "status": assessment.get("status", "UNKNOWN"),
                "critical": assessment.get("critical_triggers_count", 0),
                "anomalies_count": len(assessment.get("anomalies", [])),
                "ja4": assessment.get("tls_ja4") or "N/A"
            })

        except Exception as exc:
            logger.error(f"Execution failure during test {test_name}: {exc}", exc_info=True)
            self.results.append({
                "bot_name": test_name,
                "type": "Network (TLS/JA4 + Lua L7)",
                "score": 0,
                "status": "CRASHED",
                "critical": 1,
                "anomalies_count": 1,
                "ja4": "ERROR"
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

                context: BrowserContext = await browser.new_context(
                    viewport={"width": 1920, "height": 1080},
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                    locale="en-US",
                    timezone_id="America/New_York",
                    ignore_https_errors=True
                )
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

                await page.goto(self.https_base_url, wait_until="domcontentloaded", timeout=10000)
                await page.wait_for_selector("#score-display[data-ready='true']", timeout=8000)

                score_text: str = (await page.text_content("#score-display")) or "0"
                verdict_text: str = (await page.text_content("#verdict-display")) or "UNKNOWN"
                crit_text: str = (await page.text_content("#crit-count")) or "0"
                ja4_text: str = (await page.text_content("#ja4-display")) or "N/A"
                anomaly_rows: int = await page.locator("#anomalies-body tr[data-anomaly='true']").count()

                score_cleaned: int = int(score_text.replace("%", "").strip()) if score_text.replace("%", "").strip().isdigit() else 0
                crit_cleaned: int = int(crit_text.strip()) if crit_text.strip().isdigit() else 0

                await browser.close()

                self.results.append({
                    "bot_name": test_name,
                    "type": "Full Stack (TLS + JS + Lua)",
                    "score": score_cleaned,
                    "status": verdict_text.strip(),
                    "critical": crit_cleaned,
                    "anomalies_count": anomaly_rows,
                    "ja4": ja4_text.strip()
                })

        except Exception as exc:
            logger.error(f"Execution failure during test {test_name}: {exc}", exc_info=True)
            self.results.append({
                "bot_name": test_name,
                "type": "Full Stack (TLS + JS + Lua)",
                "score": 0,
                "status": "CRASHED",
                "critical": 1,
                "anomalies_count": 1,
                "ja4": "ERROR"
            })

    def render_benchmark_summary(self) -> None:
        console.print()
        console.print(Panel("[bold cyan]STEALTH & ANTI-DETECT BENCHMARK REPORT[/bold cyan]", border_style="cyan"))

        table: Table = Table(
            title="Head-to-Head Client Stealth Diagnostics (TLS + Lua L7 + JS Runtime)",
            header_style="bold magenta",
            show_lines=True
        )

        table.add_column("Bot / Client Stack", style="white", width=26)
        table.add_column("Inspection Scope", style="cyan", width=26)
        table.add_column("Extracted JA4", style="green", width=28)
        table.add_column("Score", justify="center", width=8)
        table.add_column("Crit / Total", justify="center", width=12)
        table.add_column("Verdict", style="bold", width=28)

        for res in self.results:
            score: int = res["score"]
            if score >= 85:
                score_str: str = f"[bold green]{score}%[/bold green]"
                status_str: str = f"[green]{res['status']}[/green]"
            elif score >= 50:
                score_str = f"[bold yellow]{score}%[/bold yellow]"
                status_str = f"[yellow]{res['status']}[/yellow]"
            else:
                score_str = f"[bold red]{score}%[/bold red]"
                status_str = f"[red]{res['status']}[/red]"

            crit_count: int = res["critical"]
            anom_count: int = res["anomalies_count"]
            counts_str: str = f"[bold red]{crit_count}[/bold red] / {anom_count}" if crit_count > 0 else f"[green]0[/green] / {anom_count}"

            table.add_row(
                res["bot_name"],
                res["type"],
                res["ja4"],
                score_str,
                counts_str,
                status_str
            )

        console.print(table)
        console.print()

    async def execute_all(self) -> None:
        logger.info(f"Auditing prober availability at {self.http_base_url}...")
        is_ready: bool = await self.check_server_readiness()

        if not is_ready:
            logger.critical(
                f"Diagnostic server at {self.http_base_url} is unreachable. "
                "Launch via 'python main.py' or run 'python main.py --benchmark'!"
            )
            return

        logger.info(">>> Executing Test 1: Standard Python HTTP Client (Unmasked)")
        await self.run_curl_cffi_test(impersonate_target=None, test_name="Python Vanilla Client")

        logger.info(">>> Executing Test 2: curl_cffi with Chrome 124 Impersonation (TLS/JA4 Spoofing)")
        await self.run_curl_cffi_test(impersonate_target="chrome124", test_name="curl_cffi (Chrome 124)")

        logger.info(">>> Executing Test 3: Playwright Chromium (Standard Headless over HTTPS/TLS)")
        await self.run_playwright_test(stealth_mode=False, test_name="Playwright Vanilla Headless")

        logger.info(">>> Executing Test 4: Playwright Chromium (Stealth Patched over HTTPS/TLS)")
        await self.run_playwright_test(stealth_mode=True, test_name="Playwright Stealth Patched")

        self.render_benchmark_summary()


async def main() -> None:
    runner: BotBenchmarkRunner = BotBenchmarkRunner()
    await runner.execute_all()


if __name__ == "__main__":
    asyncio.run(main())