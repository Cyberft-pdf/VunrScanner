from collections import deque
from dataclasses import dataclass, field
from typing import Callable

LOG_MAXLEN = 22

KIND_STYLE = {
    "TCP":  ("bold blue",    "TCP "),
    "DNS":  ("bold yellow",  "DNS "),
    "GET":  ("bold green",   "GET "),
    "DIR":  ("bold orange3", "DIR "),
    "CHK":  ("bold red",     "CHK "),
    "SSL":  ("bold cyan",    "SSL "),
    "TECH": ("bold magenta", "TECH"),
}


@dataclass
class LogEntry:
    kind: str
    target: str
    status: str
    detail: str = ""
    positive: bool = False


LogCallback = Callable[[str, str, str, str, bool], None]


class PacketLog:
    def __init__(self) -> None:
        self._entries: deque[LogEntry] = deque(maxlen=LOG_MAXLEN)

    def log(self, kind: str, target: str, status: str, detail: str = "", positive: bool = False) -> None:
        self._entries.append(LogEntry(kind, target, status, detail, positive))

    def callback(self) -> LogCallback:
        return self.log

    def entries(self) -> list[LogEntry]:
        return list(self._entries)
