"""Локальная база SHA-256 сигнатур без сетевого автообновления."""

import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

HASH_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def atomic_json(path: Path, data: dict) -> None:
    """Записать JSON через временный файл с заменой назначения."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=".viruswall-", dir=path.parent)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name != "nt":
            os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def sha256_file(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    """Потоково вычислить SHA-256 файла; файл целиком в память не загружается."""
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


class SignatureDatabase:
    """JSON-хранилище сигнатур с атомарным сохранением изменений."""

    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser()
        self._entries: dict[str, dict[str, str]] = {}
        self.reload()

    def reload(self) -> None:
        if not self.path.exists():
            self._save({EICAR_SHA256: {"name": "EICAR-Test-File", "category": "test"}})
            return
        data = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("signatures"), dict):
            raise ValueError("Некорректный формат базы сигнатур")
        entries = data["signatures"]
        checked = {}
        for digest, item in entries.items():
            if not HASH_PATTERN.fullmatch(digest) or not isinstance(item, dict):
                raise ValueError("Некорректная сигнатура")
            name, category = item.get("name"), item.get("category")
            if not isinstance(name, str) or not name.strip() or not isinstance(category, str) or not category.strip():
                raise ValueError("Некорректное имя или категория сигнатуры")
            checked[digest.lower()] = {"name": name, "category": category}
        self._entries = checked

    def lookup(self, digest: str) -> dict[str, str] | None:
        return self._entries.get(digest.lower())

    def list(self) -> dict[str, dict[str, str]]:
        return {digest: item.copy() for digest, item in self._entries.items()}

    def add(self, digest: str, name: str, category: str = "test") -> None:
        if not HASH_PATTERN.fullmatch(digest):
            raise ValueError("SHA-256 должен содержать 64 шестнадцатеричных символа")
        if not name.strip() or not category.strip():
            raise ValueError("Имя и категория обязательны")
        updated = self.list()
        updated[digest.lower()] = {"name": name.strip(), "category": category.strip()}
        self._save(updated)

    def remove(self, digest: str) -> bool:
        updated = self.list()
        removed = updated.pop(digest.lower(), None) is not None
        if removed:
            self._save(updated)
        return removed

    def update(self, entries: dict[str, dict[str, str]]) -> None:
        """Заменить базу локально переданным проверенным набором сигнатур."""
        checked = {}
        for digest, item in entries.items():
            if not HASH_PATTERN.fullmatch(digest) or not isinstance(item, dict):
                raise ValueError("Некорректная сигнатура")
            name, category = item.get("name"), item.get("category")
            if not isinstance(name, str) or not name.strip() or not isinstance(category, str) or not category.strip():
                raise ValueError("Некорректное имя или категория")
            checked[digest.lower()] = {"name": name.strip(), "category": category.strip()}
        self._save(checked)

    def _save(self, entries: dict[str, dict[str, str]]) -> None:
        atomic_json(self.path, {"version": 1, "signatures": entries})
        self._entries = entries
