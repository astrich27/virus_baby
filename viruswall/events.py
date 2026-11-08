"""Централизованная запись и просмотр событий безопасности с защитой от изменения.

Журнал формирует хеш-цепочку: каждая запись содержит SHA-256 предыдущей записи,
поэтому подмена или удаление события обнаруживается проверкой целостности.
При достижении лимита размера журнал ротируется; записи старше срока хранения
удаляются при включении обслуживания."""

import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from threading import Lock
from typing import Callable

from .models import SecurityEvent

GENESIS = "0" * 12


class EventJournal:
    """Потокобезопасный JSONL-журнал с ротацией, сроком хранения и хеш-цепочкой."""

    def __init__(self, path: str | Path, settings: dict | None = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        settings = settings or {}
        self.rotation_bytes = max(0, int(settings.get("rotation_mb", 100))) * 1024 * 1024
        self.retention_days = int(settings.get("retention_days", 90))
        self.backup_files = int(settings.get("backup_files", 3))
        self._lock = Lock()
        self._subscribers: list[Callable[[dict], None]] = []
        self._tail_hash = self._load_tail_hash()

    def subscribe(self, callback: Callable[[dict], None]) -> None:
        self._subscribers.append(callback)

    def _load_tail_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        try:
            with self.path.open("rb") as stream:
                stream.seek(0, os.SEEK_END)
                size = stream.tell()
                stream.seek(max(0, size - 4096))
                lines = stream.read().decode("utf-8", errors="replace").splitlines()
            for line in reversed(lines):
                if line.strip():
                    return self._chain_hash_of(json.loads(line))
        except (OSError, ValueError):
            return self._recompute_tail_hash()
        return GENESIS

    def _recompute_tail_hash(self) -> str:
        last = GENESIS
        try:
            with self.path.open(encoding="utf-8") as stream:
                for line in stream:
                    if line.strip():
                        try:
                            last = self._chain_hash_of(json.loads(line))
                        except (ValueError, KeyError):
                            continue
        except OSError:
            return GENESIS
        return last

    @staticmethod
    def _payload(record: dict) -> bytes:
        without = {key: value for key, value in record.items() if key != "chain_hash"}
        return json.dumps(without, ensure_ascii=False, sort_keys=True).encode("utf-8")

    def _chain_hash_of(self, record: dict) -> str:
        digest = hashlib.sha256()
        digest.update(record.get("prev_hash", "").encode("utf-8"))
        digest.update(self._payload({k: v for k, v in record.items() if k != "chain_hash"}))
        return digest.hexdigest()[:16]

    def append(self, event: SecurityEvent) -> dict:
        serialized = json.dumps(event.to_dict(), ensure_ascii=False)
        with self._lock:
            self._rotate_if_needed()
            record = json.loads(serialized)
            record["event_id"] = uuid.uuid4().hex
            record["prev_hash"] = self._tail_hash
            record["chain_hash"] = self._chain_hash_of(record)
            line = json.dumps(record, ensure_ascii=False) + "\n"
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as stream:
                stream.write(line)
                stream.flush()
                os.fsync(stream.fileno())
            self._tail_hash = record["chain_hash"]
        self._retention()
        for callback in tuple(self._subscribers):
            try:
                callback(record)
            except Exception:
                # Ошибка уведомления не отменяет сохранённое событие.
                continue
        return record

    def _rotate_if_needed(self) -> None:
        """Ротировать журнал перед записью, если достигнут лимит размера."""
        if not self.rotation_bytes:
            return
        try:
            current = self.path.stat().st_size
        except OSError:
            return
        if current < self.rotation_bytes:
            return
        for index in range(self.backup_files - 1, 0, -1):
            source = self.path.with_suffix(self.path.suffix + f".{index}")
            target = self.path.with_suffix(self.path.suffix + f".{index + 1}")
            if source.exists():
                os.replace(source, target)
        os.replace(self.path, self.path.with_suffix(self.path.suffix + ".1"))
        self._tail_hash = GENESIS  # каждый файл журнала проверяется независимо

    def _retention(self) -> None:
        """Удалить ротированные журналы, старше срока хранения (фоновая очистка)."""
        if not self.retention_days:
            return
        cutoff = time.time() - self.retention_days * 86400
        for index in range(1, self.backup_files + 1):
            candidate = self.path.with_suffix(self.path.suffix + f".{index}")
            try:
                if candidate.exists() and candidate.stat().st_mtime_ns / 1e9 < cutoff:
                    candidate.unlink()
            except OSError:
                continue

    def verify(self) -> dict:
        """Проверить хеш-цепочку журнала; вернуть первый повреждённый элемент."""
        records = [item for item in self.read(limit=1_000_000, raw=True)]
        expected = GENESIS
        for position, record in enumerate(records):
            if record.get("prev_hash") != expected or self._chain_hash_of(record) != record.get("chain_hash"):
                return {"valid": False, "records": len(records), "first_bad_index": position,
                        "event_id": record.get("event_id")}
            expected = record["chain_hash"]
        return {"valid": True, "records": len(records), "first_bad_index": None, "event_id": None}

    def read(self, event_type: str | None = None, source: str | None = None,
             severity: str | None = None, limit: int = 200, raw: bool = False) -> list[dict]:
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
        return found[-limit:] if raw else found[-limit:][::-1]
