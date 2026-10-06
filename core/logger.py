import logging
import sys
from rich.logging import RichHandler
from core.config import settings


def setup_logger(name: str = "antibot") -> logging.Logger:
    logger: logging.Logger = logging.getLogger(name)

    if logger.hasHandlers():
        return logger

    log_level_map: dict[str, int] = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }

    resolved_level: int = log_level_map.get(settings.log_level.upper(), logging.INFO)
    logger.setLevel(resolved_level)

    console_handler: RichHandler = RichHandler(
        rich_tracebacks=True,
        markup=True,
        show_time=True,
        show_path=False
    )
    console_handler.setLevel(resolved_level)

    log_format: str = "%(message)s"
    formatter: logging.Formatter = logging.Formatter(fmt=log_format, datefmt="[%X]")
    console_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.propagate = False

    return logger


logger: logging.Logger = setup_logger()