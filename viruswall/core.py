"""Оркестратор модулей и единая политика регистрации обнаружений."""

from pathlib import Path
from threading import Lock

from .behavior import ProcessMonitor
from .config import Config
from .events import EventJournal
from .filesystem import DirectoryMonitor, FileEvent
from .heuristic import HeuristicAnalyzer
from .models import Finding, ScanResult, SecurityEvent
from .network import NetworkAnalyzer, NetworkRules, capture_packets, list_connections
from .quarantine import Quarantine
from .scanner import FileScanner
from .signatures import SignatureDatabase


class VirusWall:
    """Единая точка доступа к сканированию, мониторингу и реагированию."""

    def __init__(self, data_dir: str | Path):
        self.data_dir = Path(data_dir).expanduser().absolute()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.config_path = self.data_dir / "config.json"
        self.config = Config.load(self.config_path)
        self.signatures = SignatureDatabase(self.data_dir / "signatures.json")
        self.journal = EventJournal(self.data_dir / "events.jsonl")
        self.quarantine = Quarantine(self.data_dir / "quarantine")
        self.process_monitor = ProcessMonitor()
        self.network_analyzer = NetworkAnalyzer(NetworkRules(**self.config.network_rules))
        self._seen_connections: set[tuple] | None = None
        self._process_lock = Lock()
        self._network_lock = Lock()
        self.monitor_errors: dict[str, str] = {}
        self._refresh_scanner()

    def _refresh_scanner(self) -> None:
        analyzers = ([HeuristicAnalyzer(self.config.heuristic_sensitivity).analyze]
                     if self.config.modules["heuristic"] else [])
        self.scanner = FileScanner(self.signatures if self.config.modules["signatures"] else None,
                                   self.config.exclusions + [str(self.data_dir)], analyzers)

    def save_config(self) -> None:
        self.config.save(self.config_path)
        self._refresh_scanner()
        self.network_analyzer.update_rules(NetworkRules(**self.config.network_rules))

    def status(self) -> dict:
        return {"modules": self.config.modules.copy(), "signature_count": len(self.signatures.list()),
                "quarantine_count": len(self.quarantine.list()), "data_dir": str(self.data_dir),
                "mode": "on-demand / passive monitoring", "monitor_errors": self.monitor_errors.copy()}

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
        item = self.quarantine.put(path, threat_name, confirm=confirm, remove_original=remove_original)
        self.journal.append(SecurityEvent("quarantine", "response", str(path), threat_name, "high",
                                          "quarantine", "original_removed" if remove_original else "copy_stored",
                                          details={"id": item["id"]}))
        return item

    def restore_file(self, item_id: str, *, confirm: bool = False, target: str | Path | None = None) -> Path:
        path = self.quarantine.restore(item_id, confirm=confirm, target=target)
        self.journal.append(SecurityEvent("restore", "response", str(path), "", "medium", "restore", "completed",
                                          details={"id": item_id}))
        return path

    def add_exclusion(self, path: str | Path) -> None:
        absolute = str(Path(path).expanduser().absolute())
        if absolute not in self.config.exclusions:
            self.config.exclusions.append(absolute)
            self.save_config()
            self.journal.append(SecurityEvent("configuration", "response", absolute, "", "medium",
                                              "exclude", "completed"))
