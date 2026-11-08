"""Локальная база сигнатур: SHA-256/MD5-хэши и байтовые шаблоны без сетевого автообновления."""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile

HASH_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
MD5_PATTERN = re.compile(r"^[0-9a-fA-F]{32}$")
HEX_PATTERN_BYTES = re.compile(r"^[0-9a-fA-F]{2,512}$")
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
DB_VERSION = 2
PATTERN_MAX_BYTES = 128


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
    return hashes_file(path, chunk_size)[0]


def hashes_file(path: str | Path, chunk_size: int = 1024 * 1024) -> tuple[str, str | None]:
    """Потоково вернуть (SHA-256, MD5) за один проход чтения файла."""
    sha = hashlib.sha256()
    md5 = hashlib.md5()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(chunk_size), b""):
            memory = memoryview(chunk)
            sha.update(memory)
            md5.update(memory)
    return sha.hexdigest(), md5.hexdigest()


def hash_stream(stream, chunk_size: int = 1024 * 1024) -> tuple[str, str | None]:
    """Вернуть (SHA-256, MD5) всего потока за один проход."""
    sha = hashlib.sha256()
    md5 = hashlib.md5()
    for chunk in iter(lambda: stream.read(chunk_size), b""):
        memory = memoryview(chunk)
        sha.update(memory)
        md5.update(memory)
    return sha.hexdigest(), md5.hexdigest()


class SignatureDatabase:
    """JSON-хранилище хэш-сигнатур и байтовых шаблонов с атомарным сохранением,
    резервной копией перед изменением и откатом при повреждении основной базы."""

    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser().absolute()
        self.backup_path = self.path.with_suffix(self.path.suffix + ".backup.json")
        self._entries: dict[str, dict[str, str]] = {}
        self._patterns: list[dict[str, str]] = []
        self.updated_at = ""
        self.revision = 0
        self.reload()

    @property
    def database_version(self) -> str:
        """Версия базы вида '2026.11.08.revN' для записей журнала."""
        date = (self.updated_at or "1970-01-01")[:10]
        return f"{date}.rev{self.revision}"

    def reload(self) -> None:
        """Проверка целостности; при повреждении основной базы — откат из резервной копии."""
        self.recovered_from_backup = False
        if not self.path.exists():
            self.updated_at = ""
            self.revision = 1
            self._save(_eicar_state(), [])
            return
        try:
            self._load(self.path)
        except (OSError, ValueError):
            if not self.backup_path.exists():
                raise
            shutil.copy2(self.backup_path, self.path)
            try:
                self._load(self.path)
            except (OSError, ValueError):
                raise ValueError("Повреждены и база сигнатур, и её резервная копия") from None
            self.recovered_from_backup = True

    def _load(self, path: Path) -> None:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("signatures"), dict):
            raise ValueError("Некорректный формат базы сигнатур")
        if data.get("version") not in (1, 2):
            raise ValueError("Неподдерживаемая версия базы сигнатур")
        self._entries = {}
        for digest, item in data["signatures"].items():
            self._entries[digest.lower()] = self._checked_hash(digest, item)
        patterns = data.get("patterns", [])
        if not isinstance(patterns, list):
            raise ValueError("Некорректный список шаблонов")
        self._patterns = [self._checked_pattern(item) for item in patterns]
        self.updated_at = str(data.get("updated_at", ""))
        self.revision = int(data.get("revision", 1))

    def _checked_hash(self, digest: str, item: dict) -> dict[str, str]:
        if not HASH_PATTERN.fullmatch(digest) or not isinstance(item, dict):
            raise ValueError("Некорректная сигнатура")
        name, category = item.get("name"), item.get("category")
        md5 = item.get("md5")
        if not isinstance(name, str) or not name.strip() or not isinstance(category, str) or not category.strip():
            raise ValueError("Некорректное имя или категория сигнатуры")
        if md5 is not None and (not isinstance(md5, str) or not MD5_PATTERN.fullmatch(md5)):
            raise ValueError("Некорректный MD5 в сигнатуре")
        entry = {"name": name, "category": category}
        if md5:
            entry["md5"] = md5.lower()
        return entry

    def _checked_pattern(self, item: dict) -> dict[str, str]:
        if not isinstance(item, dict):
            raise ValueError("Некорректный шаблон")
        name, category, pattern = item.get("name"), item.get("category"), item.get("pattern")
        if not isinstance(name, str) or not name.strip() or not isinstance(category, str) or not category.strip():
            raise ValueError("Некорректные имя или категория шаблона")
        if not isinstance(pattern, str) or not HEX_PATTERN_BYTES.fullmatch(pattern):
            raise ValueError("Шаблон должен быть шестнадцатеричной байтовой строкой")
        raw = bytes.fromhex(pattern)
        if len(raw) < 4 or len(raw) > PATTERN_MAX_BYTES:
            raise ValueError("Размер шаблона должен быть от 4 до 128 байт")
        return {"name": name.strip(), "category": category.strip(), "pattern": pattern.lower()}

    def lookup(self, digest: str) -> dict[str, str] | None:
        return self._entries.get(digest.lower())

    def lookup_md5(self, digest: str) -> dict[str, str] | None:
        for item in self._entries.values():
            if item.get("md5") == digest.lower():
                return item
        return None

    def list_patterns(self) -> list[dict[str, str]]:
        return [item.copy() for item in self._patterns]

    def match_sample(self, sample: bytes) -> list[dict[str, str]]:
        """Шаблоны, чьи байты встречаются в проверяемой выборке файла."""
        lowered = sample.lower()
        return [item for item in self._patterns if bytes.fromhex(item["pattern"]) in lowered]

    def list(self) -> dict[str, dict[str, str]]:
        return {digest: item.copy() for digest, item in self._entries.items()}

    def add(self, digest: str, name: str, category: str = "test", md5: str | None = None) -> None:
        entry = self._checked_hash(digest, {"name": name, "category": category, "md5": md5})
        updated = self.list()
        updated[digest.lower()] = entry
        self._save(updated, self.list_patterns())

    def add_pattern(self, pattern: str, name: str, category: str = "test") -> None:
        checked = self._checked_pattern({"name": name, "category": category, "pattern": pattern})
        updated = [item for item in self.list_patterns() if item["name"] != checked["name"]]
        updated.append(checked)
        self._save(self.list(), updated)

    def remove_pattern(self, name: str) -> bool:
        kept = [item for item in self.list_patterns() if item["name"] != name]
        if len(kept) == len(self._patterns):
            return False
        self._save(self.list(), kept)
        return True

    def remove(self, digest: str) -> bool:
        updated = self.list()
        removed = updated.pop(digest.lower(), None) is not None
        if removed:
            self._save(updated, self.list_patterns())
        return removed

    def update(self, entries: dict) -> None:
        """Заменить базу целиком переданным проверенным набором (для модуля обновлений)."""
        if not isinstance(entries, dict) or "signatures" not in entries:
            raise ValueError("Манифест должен содержать ключ signatures")
        hashes = {}
        for digest, item in entries.get("signatures", {}).items():
            hashes[digest.lower()] = self._checked_hash(digest, item)
        patterns = [self._checked_pattern(item) for item in entries.get("patterns", [])]
        self._save(hashes, patterns)

    def _save(self, entries: dict[str, dict[str, str]], patterns: list[dict[str, str]]) -> None:
        if self.revision and self.path.exists():
            try:
                shutil.copy2(self.path, self.backup_path)
                if os.name != "nt":
                    os.chmod(self.backup_path, 0o600)
            except OSError:
                shutil.copy2(self.path, self.backup_path)
        from .models import now_utc
        self.updated_at = now_utc()
        self.revision = self.revision + 1
        state = {"version": DB_VERSION, "updated_at": self.updated_at,
                 "revision": self.revision, "signatures": entries, "patterns": patterns}
        atomic_json(self.path, state)
        self._entries = entries
        self._patterns = patterns


def _eicar_state() -> dict[str, dict[str, str]]:
    return {EICAR_SHA256: {"name": "EICAR-Test-File", "category": "test"}}
