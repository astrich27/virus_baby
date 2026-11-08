"""Карантин: AES-256-GCM, подтверждение действий, лимиты и проверка целостности."""

from pathlib import Path
import hashlib
import json
import os
import secrets
import shutil
import tempfile
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag

from .models import now_utc
from .signatures import atomic_json, sha256_file


class QuarantineExceeded(Exception):
    """Лимит карантина исчерпан; помещение приостановлено до обслуживания."""


class Quarantine:
    """Шифрует копию файла; оригинал удаляется только по отдельному подтверждению."""

    def __init__(self, root: str | Path, settings: dict | None = None):
        self.root = Path(root).expanduser().absolute()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt":
            os.chmod(self.root, 0o700)
        self.max_total_bytes = int((settings or {}).get("max_total_bytes", 10 * 1024 ** 3))
        self.max_items = int((settings or {}).get("max_items", 10000))
        self.retention_days = int((settings or {}).get("retention_days", 30))
        self.key_path = self.root / "key.bin"
        if not self.key_path.exists():
            try:
                fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                pass
            else:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(secrets.token_bytes(32))
                    stream.flush()
                    os.fsync(stream.fileno())
        self.key = self.key_path.read_bytes()
        if len(self.key) != 32:
            raise ValueError("Повреждён ключ карантина")

    def _metadata(self, item_id: str) -> Path:
        if len(item_id) != 32 or any(c not in "0123456789abcdef" for c in item_id):
            raise ValueError("Некорректный ID объекта")
        return self.root / f"{item_id}.json"

    def list(self) -> list[dict]:
        found = []
        for path in self.root.glob("*.json"):
            try:
                found.append(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                continue
        return sorted(found, key=lambda item: item.get("timestamp", ""), reverse=True)

    def total_bytes(self) -> int:
        return sum(item.get("size", 0) for item in self.list())

    def _assert_capacity(self, incoming: int) -> None:
        items = self.list()
        if len(items) >= self.max_items:
            raise QuarantineExceeded(f"Достигнут максимальный объём карантина: {self.max_items} объектов")
        if self.total_bytes() + incoming > self.max_total_bytes:
            raise QuarantineExceeded("Достигнут максимальный размер карантина; помещение приостановлено")
        usage = shutil.disk_usage(self.root)
        if usage.free < incoming + 50 * 1024 * 1024:
            raise QuarantineExceeded("Недостаточно свободного места для карантина")

    def put(self, path: str | Path, threat_name: str, *, confirm: bool = False,
            remove_original: bool = False) -> dict:
        if not confirm:
            raise PermissionError("Помещение в карантин требует подтверждения")
        source = Path(path).expanduser().absolute()
        if source.is_symlink() or not source.is_file():
            raise ValueError("Карантин принимает только обычный файл")
        if self.root == source or self.root in source.parents:
            raise ValueError("Файл уже находится в карантине")
        self._assert_capacity(source.stat().st_size)
        item_id = secrets.token_hex(16)
        nonce = secrets.token_bytes(12)
        encryptor = Cipher(algorithms.AES(self.key), modes.GCM(nonce)).encryptor()
        digest = hashlib.sha256()
        size = source.stat().st_size
        destination = self.root / f"{item_id}.bin"
        temporary = None
        try:
            fd, temporary = tempfile.mkstemp(prefix=".encrypt-", dir=self.root)
            with open(source, "rb") as src, os.fdopen(fd, "wb") as dst:
                for chunk in iter(lambda: src.read(1024 * 1024), b""):
                    digest.update(chunk)
                    dst.write(encryptor.update(chunk))
                dst.write(encryptor.finalize())
                dst.flush()
                os.fsync(dst.fileno())
            if os.name != "nt":
                os.chmod(temporary, 0o600)
            os.replace(temporary, destination)
            metadata = {"id": item_id, "original_path": str(source), "threat_name": threat_name,
                        "sha256": digest.hexdigest(), "nonce": nonce.hex(), "tag": encryptor.tag.hex(),
                        "timestamp": now_utc(), "original_removed": False, "size": size}
            atomic_json(self._metadata(item_id), metadata)
            if remove_original:
                # Удаление выполняется только после подтверждения и сохранения копии.
                if source.is_symlink() or sha256_file(source) != digest.hexdigest():
                    raise RuntimeError("Исходный файл изменился во время изоляции")
                source.unlink()
                metadata["original_removed"] = True
                atomic_json(self._metadata(item_id), metadata)
            return metadata
        finally:
            if temporary and os.path.exists(temporary):
                os.unlink(temporary)

    def restore(self, item_id: str, *, confirm: bool = False, target: str | Path | None = None) -> Path:
        if not confirm:
            raise PermissionError("Восстановление требует подтверждения")
        metadata_path = self._metadata(item_id)
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        if metadata.get("restored"):
            raise ValueError("Объект уже был восстановлен")
        destination = Path(target).expanduser().absolute() if target else Path(metadata["original_path"])
        if destination.exists() or destination.is_symlink():
            raise FileExistsError(str(destination))
        destination.parent.mkdir(parents=True, exist_ok=True)
        decryptor = Cipher(algorithms.AES(self.key),
                           modes.GCM(bytes.fromhex(metadata["nonce"]), bytes.fromhex(metadata["tag"]))).decryptor()
        digest = hashlib.sha256()
        temporary = None
        try:
            fd, temporary = tempfile.mkstemp(prefix=".restore-", dir=destination.parent)
            with (self.root / f"{item_id}.bin").open("rb") as src, os.fdopen(fd, "wb") as dst:
                for chunk in iter(lambda: src.read(1024 * 1024), b""):
                    plain = decryptor.update(chunk)
                    digest.update(plain)
                    dst.write(plain)
                try:
                    dst.write(decryptor.finalize())
                except InvalidTag as exc:
                    raise ValueError("Повреждён объект карантина или неверный ключ") from exc
                dst.flush()
                os.fsync(dst.fileno())
            if digest.hexdigest() != metadata["sha256"]:
                raise ValueError("Проверка целостности восстановленного файла не пройдена")
            # Создание через жёсткую ссылку атомарно отказывает, если путь уже занят.
            os.link(temporary, destination)
            metadata["restored"] = True
            metadata["restored_at"] = now_utc()
            atomic_json(metadata_path, metadata)
            return destination
        finally:
            if temporary and os.path.exists(temporary):
                os.unlink(temporary)

    def delete(self, item_id: str, *, confirm: bool = False, wipe_passes: int = 3) -> dict:
        """Безопасное удаление объекта карантина: перезапись шифроблока случайными байтами."""
        if not confirm:
            raise PermissionError("Удаление требует подтверждения")
        metadata_path = self._metadata(item_id)
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        blob = self.root / f"{item_id}.bin"
        if blob.exists():
            with blob.open("rb+") as stream:
                stream.seek(0, os.SEEK_END)
                length = stream.tell()
                stream.seek(0)
                for _ in range(max(1, wipe_passes)):
                    stream.seek(0)
                    remaining = length
                    while remaining > 0:
                        chunk = secrets.token_bytes(min(1024 * 1024, remaining))
                        stream.write(chunk)
                        remaining -= len(chunk)
                    stream.flush()
                    os.fsync(stream.fileno())
        try:
            blob.unlink()
        except OSError as exc:
            raise RuntimeError(f"Не удалось удалить объект карантина: {exc}") from exc
        metadata_path.unlink(missing_ok=True)
        return metadata

    def purge(self, *, confirm: bool = False) -> list[str]:
        """Удалить объекты старше срока хранения по умолчанию (retention_days)."""
        if not confirm:
            raise PermissionError("Обслуживание карантина требует подтверждения")
        cutoff = time.time() - self.retention_days * 86400
        removed = []
        for item in self.list():
            stamp = item.get("timestamp", "")
            try:
                created = time.mktime(time.strptime(stamp[:19], "%Y-%m-%dT%H:%M:%S"))
            except (ValueError, TypeError):
                continue
            if created < cutoff:
                try:
                    self.delete(item["id"], confirm=True)
                except (OSError, ValueError, RuntimeError):
                    continue
                removed.append(item["id"])
        return removed
