from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from scoring.engine import StealthAssessment
from scoring.rules import RiskSeverity

console: Console = Console()


class TerminalPresenter:

    @staticmethod
    def render_assessment(
        assessment: StealthAssessment,
        user_agent: str,
        client_ip: str = "127.0.0.1"
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

        summary_text: str = (
            f"[bold white]Целевой IP:[/bold white] [cyan]{client_ip}[/cyan]\n"
            f"[bold white]Заявленный User-Agent:[/bold white] [dim]{user_agent}[/dim]\n"
            f"[bold white]Степень маскировки (Stealth Score):[/bold white] [{score_color}]{assessment.stealth_score}%[/{score_color}]\n"
            f"[bold white]Вердикт системы:[/bold white] [{status_style}]{assessment.status}[/{status_style}]\n"
            f"[bold white]Критических пробоин:[/bold white] [red]{assessment.critical_triggers_count}[/red] | "
            f"[bold white]Суммарный штраф:[/bold white] [red]-{assessment.total_penalties} pts[/red]"
        )

        console.print()
        console.print(Panel(summary_text, title="[bold cyan]АНАЛИЗ ОТПЕЧАТКА БОТА[/bold cyan]", border_style="cyan"))

        if not assessment.anomalies:
            console.print(Panel("[bold green]Аномалий не обнаружено. Бот идеально мимикрирует под реального пользователя.[/bold green]", border_style="green"))
            console.print()
            return

        table: Table = Table(
            title="Детализированный реестр обнаруженных маркеров",
            header_style="bold magenta",
            show_lines=True
        )

        table.add_column("Уровень", style="bold", width=12, justify="center")
        table.add_column("Уязвимость / Маркер", style="white", width=34)
        table.add_column("Штраф", justify="center", width=8)
        table.add_column("Рекомендация по нейтрализации", style="cyan")

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