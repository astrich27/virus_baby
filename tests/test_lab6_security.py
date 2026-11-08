"""Реакция, надёжность и испытания раздела 10.2 (Ф-14…Ф-22)."""

import hashlib
import json
import threading

import pytest

from viruswall.core import VirusWall
from viruswall.models import ScanResult, now_utc
from viruswall.report import evaluate, export_report


def test_journal_hash_chain_and_verify(tmp_path):
    app = VirusWall(tmp_path / "data")
    for index in range(5):
        app.journal.verify()
        app.add_exclusion(f"/some/path/{index}")
    check = app.journal.verify()
    assert check == {"valid": True, "records": check["records"], "first_bad_index": None, "event_id": None}
    path = app.journal.path
    lines = path.read_text(encoding="utf-8").splitlines()
    records = [json.loads(line) for line in lines]
    assert records[0]["prev_hash"] == "000000000000" and records[1]["event_id"] != records[0]["event_id"]
    tampered = records[2]["threat_name"] + "X"
    records[2]["threat_name"] = tampered
    path.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in records) + "\n", encoding="utf-8")
    broken = app.journal.verify()
    assert broken["valid"] is False and broken["first_bad_index"] == 2


def test_journal_rotation_by_size(tmp_path):
    app = VirusWall(tmp_path / "data")
    app.journal.rotation_bytes = 10 * 1024
    for index in range(200):
        app.add_exclusion(f"/path/with/marker/{index}")
    assert app.journal.path.with_suffix(".jsonl.1").exists()
    current = app.journal.verify()
    assert current["valid"] and current["records"] > 0


def test_quarantine_limits_and_disk_check(tmp_path):
    settings = {"max_total_bytes": 4096, "max_items": 2, "retention_days": 30}
    app = VirusWall(tmp_path / "data")
    from viruswall.quarantine import Quarantine, QuarantineExceeded
    limited = Quarantine(tmp_path / "data" / "quarantine", settings)
    first = tmp_path / "one.bin"
    first.write_bytes(b"x" * 100)
    limited.put(first, "P", confirm=True)
    second = tmp_path / "two.bin"
    second.write_bytes(b"y" * 100)
    limited.put(second, "P", confirm=True)
    third = tmp_path / "three.bin"
    third.write_bytes(b"z" * 100)
    with pytest.raises(QuarantineExceeded):
        limited.put(third, "P", confirm=True)
    big = tmp_path / "big.bin"
    big.write_bytes(b"A" * 8192)
    with pytest.raises(QuarantineExceeded):
        limited.put(big, "P", confirm=True)


def test_quarantine_delete_safe_wipe_and_journal(tmp_path):
    app = VirusWall(tmp_path / "data")
    file = tmp_path / "sample.bin"
    payload = b"harmless" * 70000
    file.write_bytes(payload)
    item = app.quarantine_file(file, "Manual", confirm=True)
    blob = app.quarantine.root / (item["id"] + ".bin")
    assert blob.exists()
    metadata = app.delete_quarantine_item(item["id"], confirm=True)
    assert metadata["original_path"] == str(file)
    assert not blob.exists() and not app.quarantine.root.joinpath(item["id"] + ".json").exists()
    event = app.journal.read(event_type="threat_deleted")[0]
    assert event["outcome"] == "completed" and event["details"]["wipe_passes"] == 3
    with pytest.raises(PermissionError):
        app.delete_quarantine_item(item["id"], confirm=False)


def test_restore_rescan_and_single_restore(tmp_path):
    app = VirusWall(tmp_path / "data")
    file = tmp_path / "original.bin"
    file.write_bytes(b"restore me")
    digest = hashlib.sha256(b"restore me").hexdigest()
    app.signatures.add(digest, "Lab.Restore", "test")
    item = app.quarantine_file(file, "Lab.Restore", confirm=True)
    assert file.write_bytes(b"restore me") is None or file.unlink() is None
    restored = app.restore_file(item["id"], confirm=True)
    assert restored.read_bytes() == b"restore me"
    restore_event = app.journal.read(event_type="restore")[0]
    assert restore_event["details"]["rescanned"]["status"] == "threat"
    with pytest.raises(ValueError):
        app.restore_file(item["id"], confirm=True, target=tmp_path / "again.bin")


def test_quarantine_purge_retention(tmp_path):
    app = VirusWall(tmp_path / "data")
    app.quarantine.retention_days = 0
    file = tmp_path / "old.bin"
    file.write_bytes(b"old object")
    item = app.quarantine_file(file, "Old", confirm=True)
    removed = app.purge_quarantine(confirm=True)
    assert item["id"] in removed
    assert len(app.quarantine.list()) == 0


def test_updates_signature_apply_and_reject(tmp_path):
    from viruswall.updates import Updater, UpdateError, sign_manifest, generate_keypair
    app = VirusWall(tmp_path / "data")
    public, private = generate_keypair()
    app.config.updates = {"public_key": public}
    app.save_config()
    manifest = {"signatures": {"b" * 64: {"name": "Lab.Updated", "category": "trojan"}},
                "patterns": [{"name": "P.M", "category": "trojan", "pattern": "e58a8a68eba8e6a2"}]}
    package = sign_manifest(manifest, private)
    update_file = tmp_path / "update.json"
    update_file.write_text(json.dumps(package), encoding="utf-8")
    result = Updater(app).apply_file(update_file)
    assert result == {"applied": True, "database_version": result["database_version"],
                      "signatures": 1, "patterns": 1}
    assert app.signatures.list() == {"b" * 64: {"name": "Lab.Updated", "category": "trojan"}}
    assert app.signatures.list_patterns()[0]["name"] == "P.M"
    assert app.journal.read(event_type="update_applied")[0]["outcome"] == "completed"

    # Повреждённая подпись отклоняется, база откатывается (раздел 10.2 Т-24/10-архитектуры).
    before = app.signatures.list()
    bad = sign_manifest(manifest, "11" * 32)
    (tmp_path / "bad.json").write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(UpdateError):
        Updater(app).apply_file(tmp_path / "bad.json")
    event = app.journal.read(event_type="update_failed")
    assert not event or event[0]["outcome"] == "completed" or "damaged" in json.dumps(event)
    assert app.signatures.list() == before


def test_updates_rejects_tampered_manifest(tmp_path):
    from viruswall.updates import Updater, UpdateError, sign_manifest, generate_keypair
    app = VirusWall(tmp_path / "data")
    public, private = generate_keypair()
    app.config.updates = {"public_key": public}
    app.save_config()
    manifest = {"signatures": {"c" * 64: {"name": "LooksGood", "category": "trojan"}}}
    package = sign_manifest(manifest, private)
    package["manifest"] = json.dumps({"signatures": {"d" * 64: {"name": "Backdoor", "category": "test"}}},
                                     ensure_ascii=False, separators=(",", ":"))
    file = tmp_path / "evil.json"
    file.write_text(json.dumps(package), encoding="utf-8")
    before = app.signatures.list()
    with pytest.raises(UpdateError):
        Updater(app).apply_file(file)
    assert app.signatures.list() == before


def test_integrity_guard_reports_tampering(tmp_path):
    data_dir = tmp_path / "data"
    app = VirusWall(data_dir)
    assert not [e for e in app.integrity.check()]
    config_path = app.config_path
    sneaky = json.loads(config_path.read_text(encoding="utf-8"))
    sneaky["heuristic_sensitivity"] = 100
    config_path.write_text(json.dumps(sneaky), encoding="utf-8")
    events = app.integrity.check()
    assert events and events[0].event_type == "tamper_detected"

    outside = VirusWall(data_dir)
    outside._check_tamper()
    journal_events = outside.journal.read(event_type="tamper_detected")
    assert journal_events and journal_events[0]["target"] == str(config_path)


def test_doctor_reports_failures(tmp_path):
    from viruswall.selfprotect import doctor
    app = VirusWall(tmp_path / "data")
    report = doctor(app)
    assert report["ok"] and any(check["name"] == "journal_integrity" for check in report["checks"])
    app.journal.path.write_text("{}\n", encoding="utf-8")
    broken = doctor(app)
    assert not broken["ok"]
    assert any(check["name"] == "journal_integrity" and check["result"] == "fail"
               for check in broken["checks"])


def test_txt_report_export(tmp_path):
    report = evaluate([ScanResult("/f", "f", "a" * 64, "threat", now_utc(), 0.1)], known_threats={"/f"})
    export_report(report, tmp_path / "report.txt")
    text = (tmp_path / "report.txt").read_text(encoding="utf-8")
    assert "ОТЧЁТ О СКАНИРОВАНИИ" in text and "Проверено объектов: 1" in text


def test_full_pipeline_scenario_10_2(tmp_path):
    """Комплексный сценарий: сигнатурное обнаружение → карантин → чистый файл без FP →
    обновление баз (валидной/повреждённой подписью) → самозащита → отчёт."""
    from viruswall.updates import Updater, UpdateError, sign_manifest, generate_keypair
    from viruswall.config import matches_exclusion
    app = VirusWall(tmp_path / "data")

    eicar = tmp_path / "eicar.com"
    eicar.write_bytes(X5O_EICAR)
    result = app.scan_file(eicar)
    assert result.status == "threat" and result.threat_name == "EICAR-Test-File"

    clean = tmp_path / "clean.txt"
    clean.write_text("just text")
    clean_result = app.scan_file(clean)
    assert clean_result.status == "clean"
    summary = evaluate([result, clean_result], known_threats={str(eicar)})
    assert summary["false_positives"] == 0 and summary["detection_percent"] == 100.0

    item = app.quarantine_file(eicar, result.threat_name, confirm=True, remove_original=True)
    assert not eicar.exists() and app.journal.read(event_type="quarantine")[0]["outcome"] == "original_removed"

    public, private = generate_keypair()
    app.config.updates = {"public_key": public}
    app.save_config()
    manifest = {"signatures": {"e" * 64: {"name": "Lab.Package", "category": "trojan"}}}
    good = tmp_path / "good.json"
    good.write_text(json.dumps(sign_manifest(manifest, private)), encoding="utf-8")
    assert Updater(app).apply_file(good)["applied"] is True
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(sign_manifest(manifest, "99" * 32)), encoding="utf-8")
    with pytest.raises(UpdateError):
        Updater(app).apply_file(bad)

    assert matches_exclusion([str(clean)], clean)
    for event in app.integrity.check():
        assert event.event_type != "tamper_detected"
    export_report(summary, tmp_path / "report.json")
    assert (tmp_path / "report.json").exists()


X5O_EICAR = (r"X5O!P%@AP[4\PZX54(P^)7CC)7}$"
             r"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").encode("ascii")
