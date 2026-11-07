"""Централизованная запись и просмотр событий безопасности."""

import json
import os
from pathlib import Path
from threading import Lock
from typing import Callable

from .models import SecurityEvent


class EventJournal:
    """Потокобезопасный JSONL-журнал; подписчики получают записанное событие."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        self._subscribers: list[Callable[[SecurityEvent], None]] = []

    def subscribe(self, callback: Callable[[SecurityEvent], None]) -> None:
        self._subscribers.append(callback)

    def append(self, event: SecurityEvent) -> None:
        serialized = json.dumps(event.to_dict(), ensure_ascii=False)
        with self._lock:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as stream:
                stream.write(serialized + "\n")
                stream.flush()
                os.fsync(stream.fileno())
        for callback in tuple(self._subscribers):
            try:
                callback(event)
            except Exception:
                # Ошибка уведомления не отменяет сохранённое событие.
                continue

    def read(self, event_type: str | None = None, source: str | None = None,
             severity: str | None = None, limit: int = 200) -> list[dict]:
        if limit < 1:
            raise ValueError("limit должен быть положительным")
        if not self.path.exists():
            return []
        found = []
        with self.path.open(encoding="utf-8") as stream:
            for line in stream:
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if (event_type and item.get("event_type") != event_type or
                    source and item.get("source") != source or
                    severity and item.get("severity") != severity):
                    continue
                found.append(item)
        return found[-limit:][::-1]
