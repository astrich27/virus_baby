"""Защита в реальном времени, поведенческие шаблоны и конфигурация (Ф-09, Ф-12, Ф-23, Ф-24)."""

import hashlib
import json
import threading
import time

import pytest

from viruswall.core import VirusWall
from viruswall.filesystem import FileEvent
from viruswall.models import now_utc

X5O_EICAR = (r"X5O!P%@AP[4\PZX54(P^)7CC)7}$"
             r"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").encode("ascii")


def test_realtime_policy_detect_events(tmp_path):
    app = VirusWall(tmp_path / "data")
    from viruswall.realtime import RealtimeMonitor
    monitor = RealtimeMonitor(app, tmp_path, rescan_interval=0.05)
    target = tmp_path / "sample.bin"
    target.write_bytes(b"harmless realtime fixture")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    app.signatures.add(digest, "Lab.RT", "test")
    monitor._process_one(target, "created", 0.0)
    events = app.journal.read(source="realtime")
    assert {e["event_type"] for e in events} == {"realtime_event", "realtime_detection"}
    detection = [e for e in events if e["event_type"] == "realtime_detection"][0]
    assert detection["outcome"] == "detected" and detection["details"]["reaction_ms"] >= 0
    assert monitor.summary["files_scanned"] == 1 and monitor.summary["threats"] == 1
    assert target.exists() and len(app.quarantine.list()) == 0
    monitor.stop()


def test_realtime_auto_quarantine_requires_arm(tmp_path):
    app = VirusWall(tmp_path / "data")
    from viruswall.realtime import RealtimeMonitor
    monitor = RealtimeMonitor(app, tmp_path, rescan_interval=0.05)
    target = tmp_path / "eicar.com"
    target.write_bytes(X5O_EICAR)
    monitor.policy = "quarantine"  # политика включена, но режим не «на взводе»
    monitor._process_one(target, "created", 0.0)
    assert target.exists() and len(app.quarantine.list()) == 0
    monitor.arm()
    target2 = tmp_path / "eicar2.com"
    target2.write_bytes(X5O_EICAR)
    monitor._process_one(target2, "created", 0.0)
    assert not target2.exists() and len(app.quarantine.list()) == 1
    outcome = app.journal.read(event_type="realtime_detection")[0]
    assert outcome["outcome"] == "auto_quarantined" and outcome["details"]["quarantine_id"]
    monitor.stop()


def test_realtime_fallback_backend(tmp_path):
    app = VirusWall(tmp_path / "data")
    from viruswall.realtime import RealtimeMonitor
    monitor = RealtimeMonitor(app, tmp_path)
    monitor._native = False
    assert monitor.backend == "polling fallback"
    poller = threading.Thread(target=monitor._poll_fallback, daemon=True)
    poller.start()
    time.sleep(0.4)
    file = tmp_path / "sample.txt"
    file.write_text("payload")
    for _ in range(80):
        if monitor._queue.qsize():
            break
        time.sleep(0.05)
    assert monitor._queue.qsize() >= 1
    monitor.stop()


def test_realtime_dedupes_same_event(tmp_path):
    app = VirusWall(tmp_path / "data")
    from viruswall.realtime import RealtimeMonitor
    monitor = RealtimeMonitor(app, tmp_path, rescan_interval=0.05)
    target = tmp_path / "dup.txt"
    target.write_text("same")
    stamp = target.stat().st_mtime_ns
    monitor._push(target, "created")
    monitor._push(target, "created")
    assert monitor._queue.qsize() == 1
    monitor.stop()


def test_behavior_templates_configurable(tmp_path):
    app = VirusWall(tmp_path / "data")
    app.config.behavior_templates = [{"child_glob": "python*", "name": "Process.Layout",
                                      "risk": "medium", "description": "настроенный шаблон"}]
    app.save_config()
    reloaded = VirusWall(tmp_path / "data")
    parent = ProcessInfo = None  # placeholder removed below
    from viruswall.behavior import ProcessInfo
    parent = ProcessInfo(1, None, "explorer.exe", "/x", 1.0, "now")
    child = ProcessInfo(2, 1, "python3.9", "/x", 2.0, "now")
    snapshot = [parent, child]
    monitor = reloaded.process_monitor
    last = monitor.analyze(child, snapshot)
    assert last and last[0].name == "Process.Layout" and last[0].risk == "medium"


def test_default_templates_keep_office_rule(tmp_path):
    app = VirusWall(tmp_path / "data")
    from viruswall.behavior import ProcessInfo
    parent = ProcessInfo(10, None, "winword.exe", "/office", 1.0, "now")
    child = ProcessInfo(11, 10, "powershell.exe", "/shell", 2.0, "now")
    findings = app.process_monitor.analyze(child, [parent, child])
    assert any(f.rule == "behavior_template" and f.risk == "high" for f in findings)


def test_config_backup_and_masks(tmp_path):
    app = VirusWall(tmp_path / "data")
    app.config.exclusions.append("*.pdf.exe")
    app.save_config()  # первый save: предыдущего файла конфигурации ещё не было
    app.save_config()  # второй save создаёт резервную копию предыдущей версии
    assert (tmp_path / "data" / "config.json.bak").exists()
    assert "*.pdf.exe" in json.loads((tmp_path / "data" / "config.json.bak").read_text())["exclusions"]
    file = tmp_path / "invoice.pdf.exe"
    file.write_bytes(b"MZ")
    from viruswall.config import matches_exclusion
    assert matches_exclusion(app.config.exclusions, file)
    assert not matches_exclusion(app.config.exclusions, tmp_path / "invoice.txt")


def test_realtime_config_action_validation(tmp_path):
    app = VirusWall(tmp_path / "data")
    app.config.realtime["action_on_detection"] = "delete_everything"
    app.save_config()
    with pytest.raises(ValueError):
        VirusWall(tmp_path / "data")


def test_handle_file_event_still_works_with_masks(tmp_path):
    app = VirusWall(tmp_path / "data")
    file = tmp_path / "clean.txt"
    file.write_text("safe")
    result = app.handle_file_event(FileEvent("created", str(file), now_utc()))
    assert result is not None and result.status in ("clean", "suspicious")
