import json
import subprocess
import sys
from pathlib import Path

from viruswall.signatures import EICAR_SHA256, SignatureDatabase

ROOT = Path(__file__).resolve().parents[1]


def test_public_signature_database():
    database = SignatureDatabase(ROOT / "data" / "signatures.json")
    entries = database.list()
    assert len(entries) == 9655
    assert entries[EICAR_SHA256] == {"name": "EICAR-Test-File", "category": "test"}
    assert sum(item["category"] == "stalkerware" for item in entries.values()) == 3228
    assert sum(item["category"] == "apt" for item in entries.values()) == 270
    assert sum(item["category"] == "malware" for item in entries.values()) == 6156


def test_import_signatures_script(tmp_path):
    source = tmp_path / "source.json"
    source.write_text(json.dumps({
        "version": 2,
        "signatures": {"a" * 64: {"name": "Lab.Import", "category": "test"}},
        "patterns": [],
    }), encoding="utf-8")
    data_dir = tmp_path / "data"
    result = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "import_signatures.py"),
         "--source", str(source), "--data-dir", str(data_dir)],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    database = SignatureDatabase(data_dir / "signatures.json")
    assert database.lookup("a" * 64) == {"name": "Lab.Import", "category": "test"}
    assert database.lookup(EICAR_SHA256)["name"] == "EICAR-Test-File"
