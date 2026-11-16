#!/usr/bin/env python3
"""Импортировать JSON-базу сигнатур в каталог данных VirusWall."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from viruswall.selfprotect import InstanceLock, IntegrityGuard
from viruswall.signatures import SignatureDatabase


def merge_patterns(current: list[dict[str, str]], incoming: list[dict[str, str]]) -> list[dict[str, str]]:
    merged = {item["name"]: item for item in current}
    for item in incoming:
        merged[item["name"]] = item
    return list(merged.values())


def import_database(source: Path, data_dir: Path, replace: bool) -> dict:
    payload = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("signatures"), dict):
        raise SystemExit("Источник должен содержать объект signatures")
    data_dir.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        try:
            os.chmod(data_dir, 0o700)
        except OSError:
            pass
    lock = InstanceLock(data_dir)
    try:
        database = SignatureDatabase(data_dir / "signatures.json")
        if replace:
            entries = payload["signatures"]
            patterns = payload.get("patterns", [])
        else:
            entries = {**database.list(), **payload["signatures"]}
            patterns = merge_patterns(database.list_patterns(), payload.get("patterns", []))
        database.update({"signatures": entries, "patterns": patterns})
        IntegrityGuard(data_dir).register(database.path)
        return {
            "data_dir": str(data_dir),
            "signatures": len(database.list()),
            "patterns": len(database.list_patterns()),
            "database_version": database.database_version,
        }
    finally:
        lock.release()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Импортировать базу сигнатур в VirusWall")
    parser.add_argument("--source", type=Path, default=ROOT / "data" / "signatures.json")
    parser.add_argument("--data-dir", type=Path, default=Path.home() / ".viruswall")
    parser.add_argument("--replace", action="store_true", help="заменить базу, а не объединять")
    args = parser.parse_args(argv)
    source = args.source.expanduser().absolute()
    data_dir = args.data_dir.expanduser().absolute()
    if source == data_dir / "signatures.json":
        raise SystemExit("Источник и назначение совпадают")
    print(json.dumps(import_database(source, data_dir, args.replace), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
