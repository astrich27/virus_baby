"""Защита каталога в реальном времени на событиях ОС (watchdog) с резервным опросом.

Политика реакций задаётся конфигурацией: observe — только журнал, notify — журнал и
уведомление подписчикам, quarantine — автоматическое помещение подтверждённой угрозы
в карантин (требуется явное включение режима 'на взводе')."""

from pathlib import Path
from queue import SimpleQueue, Empty
from threading import Event, Lock, Thread
from time import monotonic

from .models import SecurityEvent, now_utc

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent
    WATCHDOG_AVAILABLE = True
except ImportError:  # pragma: no cover - зависит от окружения
    Observer = None
    FileSystemEventHandler = object
    FileCreatedEvent = FileModifiedEvent = None
    WATCHDOG_AVAILABLE = False


class _Handler(FileSystemEventHandler):
    def __init__(self, accepted):
        self.accepted = accepted

    def on_created(self, event):
        if not event.is_directory:
            self.accepted(Path(event.src_path), "created")

    def on_modified(self, event):
        if not event.is_directory:
            self.accepted(Path(event.src_path), "modified")


class RealtimeMonitor:
    """Собирает события FS, дедуплицирует по (путь, момент) и запускает реакцию ядра."""

    def __init__(self, core, root: str | Path, *, rescan_interval: float = 0.25):
        self.core = core
        self.root = Path(root).expanduser().absolute()
        if not self.root.is_dir():
            raise NotADirectoryError(str(self.root))
        self.rescan_interval = max(0.05, rescan_interval)
        self.policy = core.config.realtime["action_on_detection"]
        self.armed = False
        self.summary = {"files_scanned": 0, "threats": 0, "quarantined": 0, "max_reaction_ms": 0.0}
        self._queue: SimpleQueue[tuple[Path, str, float]] = SimpleQueue()
        self._lock = Lock()
        self._recent: dict[str, tuple[str, str]] = {}
        self._stop = Event()
        self.subscribers = []
        self.observer = None
        self._poller = None
        self.worker = None
        self._native = WATCHDOG_AVAILABLE
        if WATCHDOG_AVAILABLE:
            self.observer = Observer(timeout=0.1)
            self.observer.schedule(_Handler(self._push), str(self.root), recursive=True)

    def _push(self, path: Path, event_type: str) -> None:
        try:
            detail = (event_type, path.stat().st_mtime_ns)
        except OSError:
            detail = (event_type, "gone")
        with self._lock:
            previous = self._recent.get(str(path))
            if previous == detail:
                return
            self._recent[str(path)] = detail
            if len(self._recent) > 4096:
                self._recent.clear()
        self._queue.put((path, event_type, monotonic()))

    def _poll_fallback(self) -> None:
        """Резервный режим: опрос каталога, если watchdog недоступен."""
        from .filesystem import DirectoryMonitor
        monitor = DirectoryMonitor(self.root, None, self.core.config.exclusions + [str(self.core.data_dir)])
        while not self._stop.is_set():
            for event in monitor.poll():
                self._push(Path(event.path), event.event_type)
            self._stop.wait(1.0)

    @property
    def backend(self) -> str:
        return "watchdog (native FS events)" if self._native else "polling fallback"

    def start(self) -> None:
        if self._native:
            self.observer.start()
        else:
            self._poller = Thread(target=self._poll_fallback, daemon=True)
            self._poller.start()
        self.worker = Thread(target=self._dispatch_loop, daemon=True, name="viruswall-realtime")
        self.worker.start()
        self._started = True

    def stop(self) -> None:
        self._stop.set()
        if self.observer is not None and getattr(self, "_started", False):
            self.observer.stop()
            self.observer.join(timeout=2.0)
        if self.worker is not None and self.worker.is_alive():
            self.worker.join(timeout=2.0)
        if self._poller is not None and self._poller.is_alive():
            self._poller.join(timeout=2.0)

    def _drain(self) -> list[tuple[Path, str, float]]:
        batch = []
        while True:
            try:
                batch.append(self._queue.get(timeout=self.rescan_interval))
            except Empty:
                break
            if len(batch) >= 128:
                break
        return batch

    def arm(self) -> None:
        """Явно включить автоматический карантин по политике ('на взводе')."""
        self.armed = True
        self.core.journal.append(SecurityEvent("configuration", "realtime", str(self.root), "",
                                               "medium", "arm_realtime", "completed"))

    def disarm(self) -> None:
        self.armed = False

    def _dispatch_loop(self) -> None:
        """Журналирует события, сканирует новые/изменённые файлы, применяет политику."""
        while not self._stop.is_set():
            for path, event_type, received in self._drain():
                if self._stop.is_set():
                    return
                self._process_one(path, event_type, received)

    def _process_one(self, path: Path, event_type: str, received: float) -> None:
        self.core.journal.append(SecurityEvent(
            "realtime_event", "realtime", str(path), "", "low", "observe", "queued",
            details={"event_type": event_type, "engine_version": self.core.engine_version,
                     "database_version": self.core.signatures.database_version}))
        if not isinstance(path, Path):
            return
        if not path.exists():
            return
        result = self.core.scan_file(path)
        reaction_ms = (monotonic() - received) * 1000.0
        with self._lock:
            self.summary["files_scanned"] += 1
            self.summary["max_reaction_ms"] = max(self.summary["max_reaction_ms"], round(reaction_ms, 2))
        if result.status == "clean":
            return
        if result.status == "threat":
            self.summary["threats"] += 1
        action = self.policy
        outcome = "detected"
        details = {"reaction_ms": round(reaction_ms, 2), "action": action,
                   "engine_version": self.core.engine_version,
                   "database_version": self.core.signatures.database_version,
                   "results": [result.to_dict()]}
        if action == "quarantine" and result.status == "threat" and self.armed:
            try:
                item = self.core.quarantine_file(path, result.threat_name or "Realtime.Threat",
                                                 confirm=True, remove_original=True)
                outcome = "auto_quarantined"
                details["quarantine_id"] = item["id"]
                with self._lock:
                    self.summary["quarantined"] += 1
            except (OSError, ValueError, PermissionError, RuntimeError):
                outcome = "quarantine_failed"
        self.core.journal.append(SecurityEvent(
            "realtime_detection", "realtime", str(path), result.threat_name or result.error or "",
            "high" if result.status == "threat" else "medium", action, outcome, details=details))
        for callback in tuple(self.subscribers):
            try:
                callback(result, details)
            except Exception:
                continue
