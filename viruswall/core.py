"""Оркестратор модулей и единая политика регистрации обнаружений."""

import os
from pathlib import Path
from threading import Lock

from .behavior import ProcessMonitor
from .config import Config
from .events import EventJournal
from .filesystem import DirectoryMonitor, FileEvent
from .heuristic import HeuristicAnalyzer
from .models import Finding, ScanResult, SecurityEvent, now_utc
from .network import NetworkAnalyzer, NetworkRules, capture_packets, list_connections
from .quarantine import Quarantine, QuarantineExceeded
from .scanner import FileScanner
from .selfprotect import InstanceLock, IntegrityGuard
from .signatures import SignatureDatabase

ENGINE_VERSION = "1.1.0"


class VirusWall:
    """Единая точка доступа к сканированию, мониторингу и реагированию."""

    def __init__(self, data_dir: str | Path):
        self.data_dir = Path(data_dir).expanduser().absolute()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            try:
                os.chmod(self.data_dir, 0o700)
            except OSError:
                pass
        self.engine_version = ENGINE_VERSION
        self.lock = InstanceLock(self.data_dir)
        self.config_path = self.data_dir / "config.json"
        self.config = Config.load(self.config_path)
        if not self.config_path.exists():
            self.config.save(self.config_path)
        self.signatures = SignatureDatabase(self.data_dir / "signatures.json")
        self.journal = EventJournal(self.data_dir / "events.jsonl", self.config.logging)
        self.quarantine = Quarantine(self.data_dir / "quarantine", self.config.quarantine)
        self.integrity = IntegrityGuard(self.data_dir)
        self.integrity.register(self.config_path, overwrite=False)
        self.integrity.register(self.data_dir / "signatures.json",
                                overwrite=not self.signatures.recovered_from_backup)
        self.process_monitor = ProcessMonitor(templates=self.config.behavior_templates or None)
        self.network_analyzer = NetworkAnalyzer(NetworkRules(**self.config.network_rules))
        self._seen_connections: set[tuple] | None = None
        self._process_lock = Lock()
        self._network_lock = Lock()
        self.monitor_errors: dict[str, str] = {}
        self._refresh_scanner()
        self._check_tamper()

    def _check_tamper(self) -> None:
        """Самозащита (пользовательский уровень): регистрация посторонних изменений."""
        for event in self.integrity.check():
            self.journal.append(event)

    def save_config(self) -> None:
        self.config.save(self.config_path)
        self.integrity.register(self.config_path)
        self._refresh_scanner()
        self.network_analyzer.update_rules(NetworkRules(**self.config.network_rules))

    def _refresh_scanner(self) -> None:
        analyzers = ([HeuristicAnalyzer(self.config.heuristic_sensitivity).analyze]
                     if self.config.modules["heuristic"] else [])
        self.scanner = FileScanner(self.signatures if self.config.modules["signatures"] else None,
                                   self.config.exclusions + [str(self.data_dir)], analyzers)

    def status(self) -> dict:
        return {"modules": self.config.modules.copy(), "signature_count": len(self.signatures.list()),
                "pattern_count": len(self.signatures.list_patterns()),
                "database_version": self.signatures.database_version,
                "engine_version": self.engine_version,
                "quarantine_count": len(self.quarantine.list()), "data_dir": str(self.data_dir),
                "mode": "on-demand / passive monitoring", "monitor_errors": self.monitor_errors.copy(),
                "database_recovered_from_backup": self.signatures.recovered_from_backup}

    def scan_file(self, path: str | Path) -> ScanResult:
        result = self.scanner.scan_file(path)
        self._record_scan(result)
        return result

    def scan_directory(self, path: str | Path) -> list[ScanResult]:
        results = list(self.scanner.scan_directory(path))
        for result in results:
            self._record_scan(result)
        return results

    def _record_scan(self, result: ScanResult) -> None:
        if result.status not in {"threat", "suspicious", "error"}:
            return
        self.journal.append(SecurityEvent("file_scan", "scanner", result.path,
                                          result.threat_name or result.error or "scan_error",
                                          "high" if result.status == "threat" else "medium" if result.status == "suspicious" else "low",
                                          "notify", result.status,
                                          details={"sha256": result.sha256, "findings": [f.to_dict() for f in result.findings]}))

    def handle_file_event(self, event: FileEvent) -> ScanResult | None:
        if not self.config.modules["filesystem"]:
            return None
        if event.event_type == "deleted":
            self.journal.append(SecurityEvent("file_deleted", "filesystem", event.path, "", "low", "observe", "recorded"))
            return None
        self.journal.append(SecurityEvent("file_changed", "filesystem", event.path, "", "low", "scan", "started",
                                          details={"change": event.event_type}))
        return self.scan_file(event.path)

    def watch_directory(self, path: str | Path) -> DirectoryMonitor:
        if not self.config.modules["filesystem"]:
            raise RuntimeError("Модуль файлового мониторинга отключён")
        return DirectoryMonitor(path, self.handle_file_event, self.config.exclusions + [str(self.data_dir)])

    def realtime_monitor(self, path: str | Path, *, rescan_interval: float = 0.25):
        """Мониторинг каталога на событиях ОС в реальном времени."""
        if not self.config.modules["filesystem"]:
            raise RuntimeError("Модуль файлового мониторинга отключён")
        if not self.config.realtime["enabled"]:
            raise RuntimeError("Защита в реальном времени отключена конфигурацией")
        from .realtime import RealtimeMonitor
        monitor = RealtimeMonitor(self, path, rescan_interval=rescan_interval)
        if self.config.realtime["action_on_detection"] == "quarantine":
            monitor.arm()
        return monitor

    def realtime_enabled(self) -> bool:
        return self.config.modules["filesystem"] and self.config.realtime["enabled"]

    def new_process_findings(self) -> list[tuple[dict, list[Finding]]]:
        if not self.config.modules["behavior"]:
            return []
        with self._process_lock:
            return self._new_process_findings()

    def _new_process_findings(self) -> list[tuple[dict, list[Finding]]]:
        new, all_processes = self.process_monitor.update_snapshot()
        result = []
        for process in new:
            findings = self.process_monitor.analyze(process, all_processes)
            if findings:
                self.journal.append(SecurityEvent("process", "behavior", process.exe or process.name,
                                                  findings[0].name, findings[0].risk, "notify", "detected",
                                                  details={"pid": process.pid, "findings": [f.to_dict() for f in findings]}))
                result.append((process.to_dict(), findings))
        return result

    def network_findings(self) -> list[tuple[dict, list[Finding]]]:
        if not self.config.modules["network"]:
            return []
        with self._network_lock:
            return self._network_findings()

    def _network_findings(self) -> list[tuple[dict, list[Finding]]]:
        current = list_connections()
        keyed = {(c.protocol, c.local_ip, c.local_port, c.remote_ip, c.remote_port, c.pid) for c in current}
        new = [] if self._seen_connections is None else [c for c in current if (c.protocol, c.local_ip, c.local_port, c.remote_ip, c.remote_port, c.pid) not in self._seen_connections]
        self._seen_connections = keyed
        result = []
        for connection in new:
            findings = self.network_analyzer.analyze_connection(connection)
            if findings:
                self.journal.append(SecurityEvent("network", "network", connection.remote_ip or "",
                                                  findings[0].name, findings[0].risk, "notify", "detected",
                                                  details={"connection": connection.to_dict(), "findings": [f.to_dict() for f in findings]}))
                result.append((connection.to_dict(), findings))
        return result

    def run_background(self, stop, interval: float = 2.0) -> None:
        """Пассивно опрашивать процессы и соединения до сигнала остановки."""
        if interval <= 0:
            raise ValueError("Интервал должен быть положительным")
        while not stop.is_set():
            for name, method in (("behavior", self.new_process_findings),
                                 ("network", self.network_findings)):
                if not self.config.modules[name]:
                    continue
                try:
                    method()
                    self.monitor_errors.pop(name, None)
                except (OSError, PermissionError, RuntimeError) as exc:
                    self.monitor_errors[name] = str(exc)
            stop.wait(interval)

    def capture(self, interface: str, count: int = 20, timeout: float = 5.0):
        if not self.config.modules["network"]:
            raise RuntimeError("Сетевой модуль отключён")
        result = []
        for packet in capture_packets(interface, count, timeout):
            findings = self.network_analyzer.analyze_packet(packet)
            if findings:
                self.journal.append(SecurityEvent("packet", "network", packet.destination_ip,
                                                  findings[0].name, findings[0].risk, "notify", "detected",
                                                  details={"packet": packet.to_dict(), "findings": [f.to_dict() for f in findings]}))
            result.append((packet, findings))
        return result

    def quarantine_file(self, path: str | Path, threat_name: str, *, confirm: bool = False,
                        remove_original: bool = False) -> dict:
        try:
            item = self.quarantine.put(path, threat_name, confirm=confirm, remove_original=remove_original)
        except QuarantineExceeded as exc:
            self.journal.append(SecurityEvent("quarantine_limit", "response", str(path), threat_name,
                                              "medium", "quarantine", "refused",
                                              details={"error": str(exc)}))
            raise
        self.journal.append(SecurityEvent("quarantine", "response", str(path), threat_name, "high",
                                          "quarantine", "original_removed" if remove_original else "copy_stored",
                                          details={"id": item["id"]}))
        return item

    def restore_file(self, item_id: str, *, confirm: bool = False, target: str | Path | None = None,
                     rescan: bool = True) -> Path:
        path = self.quarantine.restore(item_id, confirm=confirm, target=target)
        scanned = None
        if rescan and self.config.modules["signatures"]:
            scanned = self.scan_file(path)
        self.journal.append(SecurityEvent("restore", "response", str(path), "", "medium", "restore", "completed",
                                          details={"id": item_id, "rescanned": scanned.to_dict() if scanned else None}))
        return path

    def delete_quarantine_item(self, item_id: str, *, confirm: bool = False,
                               wipe_passes: int = 3) -> dict:
        metadata = self.quarantine.delete(item_id, confirm=confirm, wipe_passes=wipe_passes)
        self.journal.append(SecurityEvent("threat_deleted", "response", metadata["original_path"],
                                          metadata.get("threat_name", ""), "high", "delete",
                                          "completed", details={"id": item_id, "wipe_passes": wipe_passes}))
        return metadata

    def purge_quarantine(self, *, confirm: bool = False) -> list[str]:
        removed = self.quarantine.purge(confirm=confirm)
        if removed:
            self.journal.append(SecurityEvent("quarantine_purge", "response", "", "", "low",
                                              "purge", "completed", details={"count": len(removed)}))
        return removed

    def add_exclusion(self, path: str | Path) -> None:
        absolute = str(Path(path).expanduser().absolute())
        if absolute not in self.config.exclusions:
            self.config.exclusions.append(absolute)
            self.save_config()
            self.journal.append(SecurityEvent("configuration", "response", absolute, "", "medium",
                                              "exclude", "completed"))
