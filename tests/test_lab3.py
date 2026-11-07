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
