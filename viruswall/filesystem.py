"""Кроссплатформенный мониторинг каталога опросом метаданных."""

from dataclasses import asdict, dataclass
import os
from pathlib import Path
import time
from collections.abc import Callable

from .models import now_utc


@dataclass(frozen=True)
class FileEvent:
    event_type: str
    path: str
    timestamp: str

    def to_dict(self):
        return asdict(self)


class DirectoryMonitor:
    """Фиксирует создание, изменение и удаление обычных файлов между опросами."""

    def __init__(self, root: str | Path, callback: Callable[[FileEvent], None] | None = None,
                 exclusions: list[str] | None = None):
        self.root = Path(root).expanduser().absolute()
        if not self.root.is_dir():
            raise NotADirectoryError(str(self.root))
        self.callback = callback
        self.exclusions = [Path(x).expanduser().absolute() for x in (exclusions or [])]
        self._previous = self._snapshot()

    def _excluded(self, path: Path) -> bool:
        return any(path == root or root in path.parents for root in self.exclusions)

    def _snapshot(self) -> dict[str, tuple[int, int]]:
        found = {}
        for base, dirs, files in os.walk(self.root, followlinks=False):
            parent = Path(base)
            dirs[:] = [d for d in dirs if not self._excluded(parent / d) and not (parent / d).is_symlink()]
            for name in files:
                path = parent / name
                if self._excluded(path) or path.is_symlink():
                    continue
                try:
                    st = path.stat()
                    found[str(path)] = (st.st_size, st.st_mtime_ns)
                except OSError:
                    continue
        return found

    def poll(self) -> list[FileEvent]:
        current = self._snapshot()
        events = []
        for path in sorted(current.keys() - self._previous.keys()):
            events.append(FileEvent("created", path, now_utc()))
        for path in sorted(current.keys() & self._previous.keys()):
            if current[path] != self._previous[path]:
                events.append(FileEvent("modified", path, now_utc()))
        for path in sorted(self._previous.keys() - current.keys()):
            events.append(FileEvent("deleted", path, now_utc()))
        self._previous = current
        if self.callback:
            for event in events:
                self.callback(event)
        return events

    def run(self, interval: float = 1.0, stop=None) -> None:
        if interval <= 0:
            raise ValueError("Интервал опроса должен быть положительным")
        while stop is None or not stop.is_set():
            self.poll()
            if stop is not None:
                stop.wait(interval)
            else:
                time.sleep(interval)
