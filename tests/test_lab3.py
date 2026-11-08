import hashlib

from viruswall.scanner import FileScanner
from viruswall.signatures import SignatureDatabase, sha256_file


def test_signature_crud_and_scan(tmp_path):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"harmless lab sample")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    database = SignatureDatabase(tmp_path / "signatures.json")
    database.add(digest, "Lab.Sample", "test")
    result = FileScanner(database).scan_file(target)
    assert result.status == "threat"
    assert (result.name, result.sha256, result.threat_name, result.classification) == ("sample.bin", digest, "Lab.Sample", "test")
    assert result.scanned_at and result.elapsed_seconds >= 0
    assert SignatureDatabase(database.path).lookup(digest) == {"name": "Lab.Sample", "category": "test"}
    assert database.remove(digest)
    assert FileScanner(database).scan_file(target).status == "clean"


def test_recursive_exclusions_errors_and_large_file(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "nested").mkdir()
    (root / "excluded").mkdir()
    (root / "nested" / "large.bin").write_bytes(b"A" * (3 * 1024 * 1024))
    (root / "excluded" / "hidden.bin").write_bytes(b"B")
    scanner = FileScanner(SignatureDatabase(tmp_path / "db.json"), [str(root / "excluded")])
    results = list(scanner.scan_directory(root))
    assert [item.name for item in results] == ["large.bin"]
    assert results[0].sha256 == sha256_file(root / "nested" / "large.bin")
    assert scanner.scan_file(root / "missing").status == "error"
    assert scanner.scan_file(root / "excluded" / "hidden.bin").status == "excluded"


def test_invalid_signature_rejected(tmp_path):
    database = SignatureDatabase(tmp_path / "db.json")
    try:
        database.add("bad", "name")
    except ValueError:
        pass
    else:
        raise AssertionError("invalid hash accepted")


def test_harmless_eicar_test_string(tmp_path):
    sample = (r"X5O!P%@AP[4\PZX54(P^)7CC)7}$"
              r"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").encode("ascii")
    target = tmp_path / "eicar.com"
    target.write_bytes(sample)
    database = SignatureDatabase(tmp_path / "signatures.json")
    result = FileScanner(database).scan_file(target)
    assert result.status == "threat" and result.threat_name == "EICAR-Test-File"


def test_md5_and_pattern_detection(tmp_path):
    import base64
    from viruswall.signatures import hashes_file

    sample = tmp_path / "dropper"
    sample.write_bytes(b"goto begin\nthis is a dropper sample payload\n")
    md5 = hashlib.md5(sample.read_bytes()).hexdigest()
    database = SignatureDatabase(tmp_path / "db.json")
    database.add(hashlib.sha256(b"irrelevant").hexdigest(), "Hash.Only", "test", md5=md5)

    by_md5 = FileScanner(database).scan_file(sample)
    assert (by_md5.status, by_md5.threat_name) == ("threat", "Hash.Only")
    other = tmp_path / "other"
    other.write_bytes(b"other")
    assert FileScanner(database).scan_file(other).status == "clean"

    pattern = tmp_path / "patternfile"
    pattern.write_bytes(b"Some prefix marker payload trojan.header suffix")
    marker = base64.b16encode(b"trojan.header").decode()
    database.add_pattern(marker, "Pattern.TrojanHeader", "trojan")
    found = FileScanner(database).scan_file(pattern)
    assert (found.status, found.threat_name) == ("threat", "Pattern.TrojanHeader")
    assert database.remove_pattern("Pattern.TrojanHeader") is True
    assert FileScanner(database).scan_file(pattern).status == "clean"


def test_database_backup_and_rollback(tmp_path):
    db_path = tmp_path / "sign.json"
    from viruswall.signatures import EICAR_SHA256
    clean = SignatureDatabase(db_path)
    clean.add("a" * 64, "Known.Threat", "trojan")
    db_path.write_text("{tampered", encoding="utf-8")
    restored = SignatureDatabase(db_path)
    assert restored.recovered_from_backup is True
    assert restored.lookup("a" * 64) is None
    # Откат возвращает предыдущее рабочее состояние (только безопасная EICAR-сигнатура).
    assert restored.lookup(EICAR_SHA256)["name"] == "EICAR-Test-File"


def test_invalid_pattern_rejected(tmp_path):
    database = SignatureDatabase(tmp_path / "db.json")
    for bad in ("", "zz", "414243", None):
        try:
            database.add_pattern(bad or "", "Bad", "test")
        except ValueError:
            continue
        raise AssertionError("pattern accepted")


def test_hashes_file_returns_md5(tmp_path):
    from viruswall.signatures import hashes_file
    file = tmp_path / "f.bin"
    file.write_bytes(b"data stream")
    sha, md5 = hashes_file(file)
    assert sha == hashlib.sha256(b"data stream").hexdigest()
    assert md5 == hashlib.md5(b"data stream").hexdigest()


def test_scan_throughput_benchmark(tmp_path):
    payload = (b"x" * (1024 * 1024)) * 100
    file = tmp_path / "big.bin"
    file.write_bytes(payload)
    import time
    from viruswall.scanner import FileScanner as Scanner
    scanner = Scanner(SignatureDatabase(tmp_path / "db.json"))
    started = time.monotonic()
    result = scanner.scan_file(file)
    rate = file.stat().st_size / max(time.monotonic() - started, 1e-9) / (1024 * 1024)
    assert result.status == "clean" and rate >= 40
