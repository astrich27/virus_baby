"""Обновление антивирусных баз через подписанный манифест (Ed25519).

Формат файла обновления:
{
  "manifest": "...json-строка с записями signatures/patterns/text...",
  "signature": "<hex-подпись манифеста>",
}
Открытый ключ хранится в конфигурации (updates.public_key, 64 hex-символа).
База заменяется атомарно; перед заменой создаётся резервная копия, при
отказе проверки выполняется откат на предыдущее рабочее состояние."""

from pathlib import Path
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .models import SecurityEvent


class UpdateError(ValueError):
    """Запрошенное обновление не прошло проверку и не применено."""


def generate_keypair() -> tuple[str, str]:
    """Служебная функция администратора: вернуть (публичный, приватный) ключи hex."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes_raw().hex()
    private_hex = private.private_bytes_raw().hex()
    return public, private_hex


def sign_manifest(manifest: dict, private_key_hex: str) -> dict:
    """Упаковать манифест в подписанный файл обновления."""
    if len(private_key_hex) != 64:
        raise UpdateError("Приватный ключ должен содержать 64 hex-символа")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    payload = json.dumps(manifest, ensure_ascii=False, separators=(",", ":"))
    signature = private.sign(payload.encode("utf-8"))
    return {"manifest": payload, "signature": signature.hex()}


class Updater:
    """Проверяет подписанный манифест и атомарно применяет его к базе сигнатур."""

    def __init__(self, core):
        self.core = core

    def verify_file(self, path: str | Path) -> tuple[dict, Ed25519PublicKey | None]:
        raw = Path(path).read_bytes()
        try:
            package = json.loads(raw)
            payload = package["manifest"].encode("utf-8")
            signature = bytes.fromhex(package["signature"])
        except (ValueError, KeyError, AttributeError) as exc:
            raise UpdateError("Некорректный формат файла обновления") from exc
        key_hex = self.core.config.updates.get("public_key", "")
        if not key_hex:
            raise UpdateError("Публичный ключ обновлений не настроен")
        try:
            public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex))
        except ValueError as exc:
            raise UpdateError("Публичный ключ обновлений повреждён") from exc
        try:
            public.verify(signature, payload)
        except InvalidSignature as exc:
            raise UpdateError("Подпись обновления недействительна") from exc
        try:
            manifest = json.loads(payload)
        except ValueError as exc:
            raise UpdateError("Манифест не является JSON-объектом") from exc
        return manifest, public

    def apply_file(self, path: str | Path) -> dict:
        manifest, _ = self.verify_file(path)
        previous = self.core.signatures.list()
        previous_patterns = self.core.signatures.list_patterns()
        try:
            self.core.signatures.update(manifest)
        except (ValueError, OSError, RuntimeError) as exc:
            for digest, item in previous.items():
                try:
                    self.core.signatures.add(digest, item["name"], item["category"], item.get("md5"))
                except (ValueError, OSError):
                    continue
            for pattern in previous_patterns:
                try:
                    self.core.signatures.add_pattern(pattern["pattern"], pattern["name"], pattern["category"])
                except (ValueError, OSError):
                    continue
            self.core.journal.append(SecurityEvent("update_failed", "updater", str(path), "",
                                                   "high", "rollback", "completed",
                                                   details={"error": str(exc)}))
            raise UpdateError(f"Обновление отклонено, база возвращена к рабочей версии: {exc}") from exc
        revision = self.core.signatures.revision
        self.core.integrity.register(self.core.data_dir / "signatures.json")
        self.core.journal.append(SecurityEvent(
            "update_applied", "updater", str(path), manifest.get("channel", ""),
            "medium", "replace", "completed",
            details={"database_version": self.core.signatures.database_version,
                     "engine_version": self.core.engine_version,
                     "revision": revision}))
        return {"applied": True, "database_version": self.core.signatures.database_version,
                "signatures": len(self.core.signatures.list()),
                "patterns": len(self.core.signatures.list_patterns())}
