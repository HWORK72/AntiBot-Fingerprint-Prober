from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from scoring.schemas import StealthAssessment
from scoring.rules import RiskSeverity
from network.tls_parser import TLSFingerprint

console: Console = Console()


class TerminalPresenter:

    @staticmethod
    def render_assessment(
        assessment: StealthAssessment,
        user_agent: str,
        client_ip: str = "127.0.0.1",
        tls: TLSFingerprint | None = None
    ) -> None:
        if assessment.stealth_score >= 85:
            score_color: str = "bold green"
            status_style: str = "bold green"
        elif assessment.stealth_score >= 50:
            score_color: str = "bold yellow"
            status_style: str = "bold yellow"
        else:
            score_color: str = "bold red"
            status_style: str = "bold red"

        ja3_display: str = tls.ja3 if tls else "N/A (Plain HTTP / Terminated)"
        ja4_display: str = tls.ja4 if tls else "N/A (Plain HTTP / Terminated)"
        grease_display: str = str(tls.is_grease_present) if tls else "N/A"

        summary_text: str = (
            f"[bold white]Client Host:[/bold white] [cyan]{client_ip}[/cyan]\n"
            f"[bold white]Claimed User-Agent:[/bold white] [dim]{user_agent}[/dim]\n"
            f"[bold white]Stealth Score:[/bold white] [{score_color}]{assessment.stealth_score}%[/{score_color}]\n"
            f"[bold white]Diagnostic Verdict:[/bold white] [{status_style}]{assessment.status}[/{status_style}]\n"
            f"[bold white]Critical Triggers:[/bold white] [red]{assessment.critical_triggers_count}[/red] | "
            f"[bold white]Total Penalties:[/bold white] [red]-{assessment.total_penalties} pts[/red]\n\n"
            f"[bold magenta]=== EXTRACTED TLS/L5 FINGERPRINTS ===[/bold magenta]\n"
            f"[bold white]JA3 Hash (MD5):[/bold white] [green]{ja3_display}[/green]\n"
            f"[bold white]JA4 Fingerprint:[/bold white] [bold green]{ja4_display}[/bold green]\n"
            f"[bold white]RFC 8701 GREASE Detected:[/bold white] [yellow]{grease_display}[/yellow]"
        )

        console.print()
        console.print(Panel(summary_text, title="[bold cyan]BOT FINGERPRINT AUDIT REPORT[/bold cyan]", border_style="cyan"))

        if not assessment.anomalies:
            console.print(Panel("[bold green]Zero anomalies detected. Fingerprint matches clean authentic client.[/bold green]", border_style="green"))
            console.print()
            return

        table: Table = Table(
            title="Detected Fingerprint Anomalies & Remediation Directives",
            header_style="bold magenta",
            show_lines=True
        )

        table.add_column("Severity", style="bold", width=12, justify="center")
        table.add_column("Anomaly / Vector", style="white", width=34)
        table.add_column("Penalty", justify="center", width=8)
        table.add_column("Remediation Directive", style="cyan")

        severity_colors: dict[RiskSeverity, str] = {
            RiskSeverity.CRITICAL: "red",
            RiskSeverity.HIGH: "bright_red",
            RiskSeverity.MEDIUM: "yellow",
            RiskSeverity.LOW: "blue"
        }

        for anomaly in assessment.anomalies:
            color: str = severity_colors.get(anomaly.severity, "white")
            table.add_row(
                f"[{color}]{anomaly.severity.value}[/{color}]",
                f"[bold {color}]{anomaly.title}[/bold {color}]\n[dim]{anomaly.description}[/dim]",
                f"[{color}]-{anomaly.penalty}[/{color}]",
                f"[green]{anomaly.recommendation}[/green]"
            )

        console.print(table)
        console.print()