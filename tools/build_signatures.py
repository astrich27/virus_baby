#!/usr/bin/env python3
"""Собрать публичную базу SHA-256 из источников с разрешительной лицензией."""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from viruswall.signatures import EICAR_SHA256, HASH_PATTERN, SignatureDatabase

ESET_TREE = "https://api.github.com/repos/eset/malware-ioc/git/trees/master?recursive=1"
ESET_RAW = "https://raw.githubusercontent.com/eset/malware-ioc/master/"
STALKERWARE_CSV = "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/samples.csv"
AMNESTY_RAW = "https://raw.githubusercontent.com/amnestytech/investigations/master/"
AMNESTY_FILES = {
    "2020-06-15_india/sha256.txt": "2020-06-15_india",
    "2020-09-25_finfisher/sha256.csv": "2020-09-25_finfisher",
    "2021-02-24_vietnam/indicators/sha256.txt": "2021-02-24_vietnam",
    "2021-10-07_donot/sha256.txt": "2021-10-07_donot",
    "2024-12-16_serbia_novispy/sha256.txt": "2024-12-16_serbia_novispy",
}
USER_AGENT = "VirusWall-signature-builder/1.0"
SHA256_TOKEN = re.compile(r"[0-9a-fA-F]{64}")


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.read()
        except OSError:
            if attempt == 2:
                raise
    raise RuntimeError("unreachable")


def add(entries: dict[str, dict[str, str]], digest: str, name: str, category: str) -> None:
    digest = digest.lower()
    if HASH_PATTERN.fullmatch(digest):
        entries.setdefault(digest, {"name": name.strip(), "category": category.strip()})


def load_eset(entries: dict[str, dict[str, str]]) -> int:
    tree = json.loads(fetch(ESET_TREE).decode("utf-8"))
    paths = [
        item["path"]
        for item in tree.get("tree", [])
        if item.get("type") == "blob" and item["path"].endswith("samples.sha256")
    ]

    def download(path: str) -> tuple[str, str]:
        url = ESET_RAW + urllib.parse.quote(path)
        return path, fetch(url).decode("utf-8", "replace")

    found: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=12) as pool:
        for path, text in pool.map(download, paths):
            family = path.split("/", 1)[0]
            for digest in SHA256_TOKEN.findall(text):
                found.setdefault(digest.lower(), family)
    for digest, family in found.items():
        add(entries, digest, f"ESET.{family}", "malware")
    return len(found)


def load_stalkerware(entries: dict[str, dict[str, str]]) -> int:
    text = fetch(STALKERWARE_CSV).decode("utf-8-sig", "replace")
    found: dict[str, str] = {}
    for row in csv.DictReader(io.StringIO(text)):
        digest = (row.get("SHA256") or "").strip().lower()
        app = (row.get("App") or "Unknown").strip()
        if HASH_PATTERN.fullmatch(digest):
            found.setdefault(digest, app)
    for digest, app in found.items():
        add(entries, digest, f"Stalkerware.{app}", "stalkerware")
    return len(found)


def load_amnesty(entries: dict[str, dict[str, str]]) -> int:
    found: dict[str, str] = {}
    for path, campaign in AMNESTY_FILES.items():
        text = fetch(AMNESTY_RAW + urllib.parse.quote(path)).decode("utf-8", "replace")
        for digest in SHA256_TOKEN.findall(text):
            found.setdefault(digest.lower(), campaign)
    for digest, campaign in found.items():
        add(entries, digest, f"Amnesty.{campaign}", "apt")
    return len(found)


def load_eicar(entries: dict[str, dict[str, str]]) -> int:
    add(entries, EICAR_SHA256, "EICAR-Test-File", "test")
    return 1


def build(output: Path) -> dict:
    entries: dict[str, dict[str, str]] = {}
    sources = {
        "eicar": load_eicar(entries),
        "eset": load_eset(entries),
        "stalkerware": load_stalkerware(entries),
        "amnesty": load_amnesty(entries),
    }
    revision = 1
    if output.exists():
        try:
            revision = int(json.loads(output.read_text(encoding="utf-8")).get("revision", 0)) + 1
        except (OSError, ValueError, TypeError):
            revision = 1
    updated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    state = {
        "version": 2,
        "updated_at": updated_at,
        "revision": revision,
        "signatures": dict(sorted(entries.items())),
        "patterns": [],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    database = SignatureDatabase(output)
    if len(database.list()) != len(entries):
        raise SystemExit("Записанная база не прошла проверку целостности")
    return {
        "output": str(output),
        "signatures": len(entries),
        "sources": sources,
        "revision": revision,
        "updated_at": updated_at,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Собрать публичную базу сигнатур VirusWall")
    parser.add_argument("--output", type=Path, default=ROOT / "data" / "signatures.json")
    args = parser.parse_args(argv)
    print(json.dumps(build(args.output.expanduser().absolute()), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
