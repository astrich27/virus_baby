"""Карантин с AES-256-GCM, подтверждением и проверкой целостности."""

from pathlib import Path
import hashlib
import json
import os
import secrets
import tempfile

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag

from .models import now_utc
from .signatures import atomic_json, sha256_file


class Quarantine:
    """Шифрует копию файла; оригинал удаляется только по отдельному подтверждению."""

    def __init__(self, root: str | Path):
        self.root = Path(root).expanduser().absolute()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt":
            os.chmod(self.root, 0o700)
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

    def put(self, path: str | Path, threat_name: str, *, confirm: bool = False,
            remove_original: bool = False) -> dict:
        if not confirm:
            raise PermissionError("Помещение в карантин требует подтверждения")
        source = Path(path).expanduser().absolute()
        if source.is_symlink() or not source.is_file():
            raise ValueError("Карантин принимает только обычный файл")
        if self.root == source or self.root in source.parents:
            raise ValueError("Файл уже находится в карантине")
        item_id = secrets.token_hex(16)
        nonce = secrets.token_bytes(12)
        encryptor = Cipher(algorithms.AES(self.key), modes.GCM(nonce)).encryptor()
        digest = hashlib.sha256()
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
                        "timestamp": now_utc(), "original_removed": False}
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
        metadata = json.loads(self._metadata(item_id).read_text(encoding="utf-8"))
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
            return destination
        finally:
            if temporary and os.path.exists(temporary):
                os.unlink(temporary)
