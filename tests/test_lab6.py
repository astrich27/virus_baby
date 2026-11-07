import hashlib

import pytest

from viruswall.core import VirusWall
from viruswall.filesystem import FileEvent
from viruswall.behavior import ProcessInfo, ProcessMonitor
from viruswall.network import ConnectionInfo, NetworkRules
from viruswall.models import ScanResult, now_utc
from viruswall.report import evaluate, export_report


def test_integration_quarantine_restore_and_journal(tmp_path):
    app = VirusWall(tmp_path / "data")
    target = tmp_path / "sample.bin"
    target.write_bytes(b"harmless fixture")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    app.signatures.add(digest, "Lab.Sample", "test")
    result = app.scan_file(target)
    assert result.status == "threat"
    assert app.journal.read()[0]["threat_name"] == "Lab.Sample"
    with pytest.raises(PermissionError):
        app.quarantine_file(target, "Lab.Sample")
    item = app.quarantine_file(target, "Lab.Sample", confirm=True, remove_original=True)
    assert not target.exists()
    assert app.quarantine.list()[0]["id"] == item["id"]
    with pytest.raises(PermissionError):
        app.restore_file(item["id"])
    restored = app.restore_file(item["id"], confirm=True)
    assert restored.read_bytes() == b"harmless fixture"
    assert app.journal.read(event_type="restore")[0]["outcome"] == "completed"


def test_config_events_and_report(tmp_path):
    app = VirusWall(tmp_path / "data")
    file = tmp_path / "clean.txt"
    file.write_text("safe")
    app.add_exclusion(file)
    assert app.scan_file(file).status == "excluded"
    app.config.modules["filesystem"] = False
    app.save_config()
    assert app.handle_file_event(FileEvent("created", str(file), now_utc())) is None
    assert VirusWall(tmp_path / "data").config.modules["filesystem"] is False
    result = ScanResult(str(file), file.name, "x" * 64, "clean", now_utc(), 0.1)
    report = evaluate([result], known_threats=set())
    assert report["files_scanned"] == 1
    assert report["false_positives"] == 0
    assert report["detection_percent"] is None
    export_report(report, tmp_path / "report.json")
    assert (tmp_path / "report.json").exists()


def test_quarantine_does_not_overwrite_existing_file(tmp_path):
    app = VirusWall(tmp_path / "data")
    file = tmp_path / "original.bin"
    file.write_bytes(b"safe test")
    item = app.quarantine_file(file, "Manual", confirm=True)
    assert file.read_bytes() == b"safe test"
    with pytest.raises(FileExistsError):
        app.restore_file(item["id"], confirm=True)
    assert app.quarantine.list()[0]["id"] == item["id"]


def test_filesystem_process_network_share_journal(tmp_path, monkeypatch):
    app = VirusWall(tmp_path / "data")
    watched = tmp_path / "watched"
    watched.mkdir()
    monitor = app.watch_directory(watched)
    file = watched / "sample.txt"
    file.write_text("harmless")
    monitor.poll()
    assert not app.journal.read(event_type="file_scan")
    parent = ProcessInfo(10, None, "winword.exe", "/office", 1.0, "now")
    child = ProcessInfo(11, 10, "powershell.exe", "/shell", 2.0, "now")
    snapshots = [[parent], [parent, child]]
    app.process_monitor = ProcessMonitor(lambda: snapshots.pop(0))
    assert app.new_process_findings() == []
    assert len(app.new_process_findings()) == 1
    app.network_analyzer.update_rules(NetworkRules(suspicious_ips=("203.0.113.10",)))
    connection = ConnectionInfo("tcp", "127.0.0.1", 5000, "203.0.113.10", 443,
                                "ESTABLISHED", 11, "outbound_inferred", "now")
    connections = [[], [connection]]
    monkeypatch.setattr("viruswall.core.list_connections", lambda: connections.pop(0))
    assert app.network_findings() == []
    assert len(app.network_findings()) == 1
    assert {e["source"] for e in app.journal.read()} >= {"behavior", "network"}


def test_quarantine_detects_tampering(tmp_path):
    app = VirusWall(tmp_path / "data")
    file = tmp_path / "sample.bin"
    file.write_bytes(b"safe")
    item = app.quarantine_file(file, "Manual", confirm=True)
    encrypted = app.quarantine.root / (item["id"] + ".bin")
    encrypted.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="Повреждён объект"):
        app.restore_file(item["id"], confirm=True, target=tmp_path / "restored.bin")
    assert not (tmp_path / "restored.bin").exists()


def test_desktop_window_and_scan(tmp_path):
    import os
    import subprocess
    import sys
    file = tmp_path / "clean.txt"
    file.write_text("safe test")
    code = '''
import sys
from pathlib import Path
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication
from viruswall.core import VirusWall
from viruswall.ui import VirusWallWindow
qt = QApplication([])
window = VirusWallWindow(VirusWall(sys.argv[1]))
assert window.tabs.count() == 8
def start():
    window._start_scan(Path(sys.argv[2]))
    window._scan_worker.finished.connect(qt.quit)
QTimer.singleShot(0, start)
QTimer.singleShot(10000, qt.quit)
qt.exec()
assert window.scan_table.rowCount() == 1
assert window.scan_table.item(0, 2).text() == "clean"
window.close()
'''
    env = os.environ.copy()
    env["QT_QPA_PLATFORM"] = "offscreen"
    result = subprocess.run([sys.executable, "-c", code, str(tmp_path / "data"), str(file)],
                            env=env, capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr


def test_cli_scan_and_export(tmp_path, capsys):
    from viruswall.cli import main
    target = tmp_path / "fixture.txt"
    target.write_text("safe demo")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    data = tmp_path / "data"
    assert main(["--data-dir", str(data), "signature", "add", digest, "Lab.CLI"]) == 0
    report = tmp_path / "report.csv"
    assert main(["--data-dir", str(data), "scan", str(target), "--report", str(report)]) == 0
    output = capsys.readouterr().out
    assert '"status": "threat"' in output
    text = report.read_text()
    assert text.startswith("metric,value")
    assert "fixture.txt" in text and "Lab.CLI" in text


def test_background_monitor_handles_os_denial(tmp_path):
    import threading
    app = VirusWall(tmp_path / "data")
    stop = threading.Event()
    calls = []
    def denied_processes():
        calls.append("process")
        raise PermissionError("no access")
    def network_once():
        calls.append("network")
        stop.set()
        return []
    app.new_process_findings = denied_processes
    app.network_findings = network_once
    app.run_background(stop, interval=0.01)
    assert calls == ["process", "network"]
    assert app.status()["monitor_errors"]["behavior"] == "no access"
