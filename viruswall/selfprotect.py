"""Самозащита пользовательского уровня: одиночный экземпляр, права, целостность хранения.

Полного пользовательского уровня недостаточно против администратора; механизм
защищает от другого экземпляра приложения, случайного изменения конфигурации
и базы, и регистрирует подозрительные модификации в журнале."""

import fcntl
import json
import os
from pathlib import Path

from .models import SecurityEvent, now_utc
from .signatures import atomic_json

try:
    import msvcrt  # type: ignore
except ImportError:
    msvcrt = None


class InstanceLock:
    """Гарантирует единственный работающий экземпляр на каталог данных."""

    _owners: dict = {}

    def __init__(self, data_dir: Path):
        self.path = Path(data_dir) / "viruswall.lock"
        self._stream = None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        key = str(self.path.absolute())
        if key in InstanceLock._owners and InstanceLock._owners[key] is not None:
            # Повторное создание в том же процессе (модульные тесты/перезагрузка ядра).
            self._stream = InstanceLock._owners[key]
            return
        stream = open(self.path, "w")
        try:
            os.chmod(self.path, 0o600)
            if msvcrt:
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            stream.close()
            raise RuntimeError("VirusWall уже запущен для этого каталога данных") from exc
        self._stream = stream
        stream.write(str(os.getpid()))
        stream.flush()
        InstanceLock._owners[key] = stream

    def release(self) -> None:
        if self._stream is None:
            return
        key = str(self.path.absolute())
        if InstanceLock._owners.get(key) is self._stream:
            InstanceLock._owners.pop(key, None)
        try:
            if msvcrt:
                self._stream.seek(0)
                msvcrt.locking(self._stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(self._stream.fileno(), fcntl.LOCK_UN)
        finally:
            self._stream.close()
            self._stream = None


class IntegrityGuard:
    """Хранит контрольные суммы конфигурации и базы; фиксирует посторонние изменения."""

    def __init__(self, data_dir: Path):
        self.path = Path(data_dir) / "integrity.json"

    def _load(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _save(self, state: dict) -> None:
        atomic_json(self.path, state)

    def register(self, file: str | Path, overwrite: bool = True) -> None:
        """Зафиксировать контрольную сумму файла.

        overwrite=False только впервые добавляет файл в контроль: он не
        затирает ранее подтверждённую сумму — так честные изменения, внесённые
        приложением, подтверждает save_config/Updater, а посторонние правки
        остаётся зафиксировать через check().
        """
        target = Path(file)
        if not target.exists():
            return
        state = self._load()
        key = str(target)
        if not overwrite and key in state:
            return
        state[key] = self._digest(target)
        self._save(state)

    @staticmethod
    def _digest(target: Path) -> str:
        import hashlib
        return hashlib.sha256(target.read_bytes()).hexdigest()

    def check(self) -> list[SecurityEvent]:
        """Сравнить текущие суммы с сохранёнными; вернуть события о подмене."""
        state = self._load()
        events = []
        for path_text, stored in state.items():
            target = Path(path_text)
            if not target.exists():
                continue
            if self._digest(target) != stored:
                events.append(SecurityEvent(
                    "tamper_detected", "selfprotection", path_text,
                    "", "high", "notify", "detected",
                    details={"description": "Файл изменён вне приложения после последнего подтверждения",
                             "timestamp": now_utc()}))
        return events

    def permissions_report(self, data_dir: Path) -> list[str]:
        """Проверить права каталога данных и предупредить о общедоступных файлах."""
        warnings = []
        if os.name == "nt":
            return warnings
        mode = data_dir.stat().st_mode & 0o777
        if mode & 0o077:
            warnings.append(f"Каталог данных доступен другим пользователям: {mode:o}")
        for candidate in data_dir.iterdir():
            if candidate.is_file() and candidate.stat().st_mode & 0o077:
                warnings.append(f"Файл {candidate.name} доступен другим пользователям")
        return warnings


def doctor(core) -> dict:
    """Самотестирование компонентов (раздел 11.1 руководства по развёртыванию)."""
    report = {"ok": True, "checks": []}

    def check(name: str, condition: bool, detail: str = "") -> None:
        report["checks"].append({"name": name, "result": "ok" if condition else "fail", "detail": detail})
        if not condition:
            report["ok"] = False

    modules = []
    for module_name in ("psutil", "scapy", "cryptography"):
        try:
            __import__(module_name)
            modules.append(module_name)
        except ImportError:
            pass
    try:
        import watchdog  # noqa: F401
        modules.append("watchdog")
        native_rt = True
    except ImportError:
        native_rt = False
    check("dependencies", set(modules) >= {"psutil", "cryptography"},
          f"установлены: {', '.join(modules) or 'нет'}")
    check("realtime_native_backend", native_rt, "watchdog" if native_rt else "резервный опрос каталога")
    check("password_dir_permissions", not core.integrity.permissions_report(core.data_dir),
          "; ".join(core.integrity.permissions_report(core.data_dir)))
    check("quarantine_key", len(getattr(core.quarantine, "key", b"")) == 32)
    journal_check = core.journal.verify()
    check("journal_integrity", journal_check["valid"], json.dumps(journal_check, ensure_ascii=False))
    check("database_loadable", isinstance(core.signatures, object))
    check("database_recovered", not core.signatures.recovered_from_backup,
          "использована резервная копия" if core.signatures.recovered_from_backup else "")
    free = None
    try:
        import shutil
        free = shutil.disk_usage(core.data_dir).free
    except OSError:
        pass
    check("disk_space", bool(free and free > 100 * 1024 * 1024),
          f"{free / (1024 ** 2):.0f} МБ свободно" if free else "неизвестно")
    return report
