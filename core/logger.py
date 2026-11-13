from collections.abc import Callable
import logging
from pathlib import Path
import re
import sys
import threading
from typing import Any, TextIO
from rich.console import Console
from rich.logging import RichHandler
from core.config import settings

BASE_DIR: Path = Path(__file__).resolve().parent.parent
LOG_FILE_PATH: Path = BASE_DIR / "logs.txt"

ANSI_ESCAPE_REGEX: re.Pattern[str] = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
RICH_TAG_REGEX: re.Pattern[str] = re.compile(
    r"\[/?(?:bold|dim|italic|underline|cyan|green|red|yellow|magenta|white|bright_red|blue)(?:\s+(?:bold|dim|italic|underline|cyan|green|red|yellow|magenta|white|bright_red|blue))*\]"
)

_ORIGINAL_STDOUT: TextIO = sys.stdout
_ORIGINAL_STDERR: TextIO = sys.stderr

_stdout_reconfigure: Callable[..., None] | None = getattr(_ORIGINAL_STDOUT, "reconfigure", None)
if callable(_stdout_reconfigure):
    _stdout_reconfigure(encoding="utf-8", errors="replace")

_stderr_reconfigure: Callable[..., None] | None = getattr(_ORIGINAL_STDERR, "reconfigure", None)
if callable(_stderr_reconfigure):
    _stderr_reconfigure(encoding="utf-8", errors="replace")


class InstantFlushFileHandler(logging.FileHandler):

    def __init__(self, filename: Path) -> None:
        super().__init__(
            filename=str(filename),
            mode="w",
            encoding="utf-8",
            delay=False
        )

    def emit(self, record: logging.LogRecord) -> None:
        super().emit(record)
        self.flush()

    def close(self) -> None:
        self.flush()


class PlainFileFormatter(logging.Formatter):

    def format(self, record: logging.LogRecord) -> str:
        formatted: str = super().format(record)
        no_ansi: str = ANSI_ESCAPE_REGEX.sub("", formatted)
        clean_text: str = RICH_TAG_REGEX.sub("", no_ansi)
        return clean_text


class ConsoleStreamTee:

    def __init__(
        self,
        original_stream: TextIO,
        file_handler: InstantFlushFileHandler,
        write_lock: threading.Lock
    ) -> None:
        self._original_stream: TextIO = original_stream
        self._file_handler: InstantFlushFileHandler = file_handler
        self._lock: threading.Lock = write_lock

    def write(self, data: str) -> int:
        written: int = self._original_stream.write(data)
        self._original_stream.flush()
        clean_text: str = ANSI_ESCAPE_REGEX.sub("", data)
        if clean_text:
            with self._lock:
                if self._file_handler.stream is not None and not self._file_handler.stream.closed:
                    self._file_handler.stream.write(clean_text)
                    self._file_handler.stream.flush()
        return written

    def flush(self) -> None:
        self._original_stream.flush()
        with self._lock:
            if self._file_handler.stream is not None and not self._file_handler.stream.closed:
                self._file_handler.stream.flush()

    def isatty(self) -> bool:
        return self._original_stream.isatty()

    def fileno(self) -> int:
        return self._original_stream.fileno()

    @property
    def encoding(self) -> str:
        return getattr(self._original_stream, "encoding", "utf-8")

    def __getattr__(self, name: str) -> Any:
        return getattr(self._original_stream, name)


_SINGLETON_LOGGER: logging.Logger | None = None
_LOGGER_INIT_LOCK: threading.Lock = threading.Lock()


def setup_logger(name: str = "antibot") -> logging.Logger:
    global _SINGLETON_LOGGER

    with _LOGGER_INIT_LOCK:
        if _SINGLETON_LOGGER is not None:
            return _SINGLETON_LOGGER

        target_logger: logging.Logger = logging.getLogger(name)

        log_level_map: dict[str, int] = {
            "DEBUG": logging.DEBUG,
            "INFO": logging.INFO,
            "WARNING": logging.WARNING,
            "ERROR": logging.ERROR,
            "CRITICAL": logging.CRITICAL,
        }

        resolved_level: int = log_level_map.get(settings.log_level.upper(), logging.INFO)
        target_logger.setLevel(resolved_level)

        file_handler: InstantFlushFileHandler = InstantFlushFileHandler(LOG_FILE_PATH)
        file_handler.setLevel(resolved_level)
        file_formatter: PlainFileFormatter = PlainFileFormatter(
            fmt="%(asctime)s | %(levelname)-8s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(file_formatter)

        rich_console: Console = Console(file=_ORIGINAL_STDERR, force_terminal=_ORIGINAL_STDERR.isatty())
        console_handler: RichHandler = RichHandler(
            console=rich_console,
            rich_tracebacks=True,
            markup=True,
            show_time=True,
            show_path=False
        )
        console_handler.setLevel(resolved_level)
        console_formatter: logging.Formatter = logging.Formatter(fmt="%(message)s", datefmt="[%X]")
        console_handler.setFormatter(console_formatter)

        target_logger.handlers.clear()
        target_logger.addHandler(console_handler)
        target_logger.addHandler(file_handler)
        target_logger.propagate = False

        stream_lock: threading.Lock = threading.Lock()
        sys.stdout = ConsoleStreamTee(_ORIGINAL_STDOUT, file_handler, stream_lock)
        sys.stderr = ConsoleStreamTee(_ORIGINAL_STDERR, file_handler, stream_lock)

        _SINGLETON_LOGGER = target_logger
        return target_logger


logger: logging.Logger = setup_logger()