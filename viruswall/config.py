"""Конфигурация модулей VirusWall с проверкой схемы и резервной копией перед изменением."""

from dataclasses import asdict, dataclass, field
from fnmatch import fnmatch
import json
import shutil
from pathlib import Path

DEFAULT_MODULES = {"signatures": True, "heuristic": True, "behavior": True,
                   "filesystem": True, "network": True}

DEFAULT_REALTIME = {"enabled": True, "action_on_detection": "notify",
                    "max_file_size": 268435456, "cooldown_seconds": 2}
DEFAULT_QUARANTINE = {"max_total_bytes": 10 * 1024 ** 3, "max_items": 10000, "retention_days": 30}
DEFAULT_LOGGING = {"rotation_mb": 100, "retention_days": 90, "backup_files": 3}
DEFAULT_UPDATES = {"public_key": ""}
DEFAULT_REALTIME_ACTIONS = ("observe", "notify", "quarantine")


def _nonnegative_int(value, name: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"Некорректное значение {name}")
    return value


def matches_exclusion(exclusions: list[str], path: Path) -> bool:
    target = Path(path).expanduser().absolute()
    for pattern in exclusions:
        if fnmatch(str(target), pattern) or fnmatch(target.name, pattern):
            return True
        try:
            rule = Path(pattern).expanduser().absolute()
        except ValueError:
            continue
        if target == rule or rule in target.parents:
            return True
    return False


@dataclass
class Config:
    modules: dict[str, bool] = field(default_factory=lambda: DEFAULT_MODULES.copy())
    exclusions: list[str] = field(default_factory=list)
    heuristic_sensitivity: int = 50
    monitored_directory: str = ""
    network_rules: dict = field(default_factory=dict)
    realtime: dict = field(default_factory=lambda: DEFAULT_REALTIME.copy())
    quarantine: dict = field(default_factory=lambda: DEFAULT_QUARANTINE.copy())
    logging: dict = field(default_factory=lambda: DEFAULT_LOGGING.copy())
    behavior_templates: list = field(default_factory=list)
    updates: dict = field(default_factory=lambda: DEFAULT_UPDATES.copy())

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        target = Path(path)
        if not target.exists():
            return cls()
        data = json.loads(target.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Конфигурация должна быть JSON-объектом")
        config = cls()
        modules = data.get("modules", {})
        if not isinstance(modules, dict) or any(k not in DEFAULT_MODULES or type(v) is not bool for k, v in modules.items()):
            raise ValueError("Некорректные настройки модулей")
        config.modules.update(modules)
        exclusions = data.get("exclusions", [])
        sensitivity = data.get("heuristic_sensitivity", 50)
        monitored = data.get("monitored_directory", "")
        network_rules = data.get("network_rules", {})
        if not isinstance(exclusions, list) or not all(isinstance(x, str) for x in exclusions):
            raise ValueError("Некорректные исключения")
        if type(sensitivity) is not int or not 0 <= sensitivity <= 100 or not isinstance(monitored, str):
            raise ValueError("Некорректные параметры анализа")
        if not isinstance(network_rules, dict):
            raise ValueError("Некорректные сетевые правила")
        from .network import NetworkRules
        try:
            NetworkRules(**network_rules)
        except (TypeError, ValueError) as exc:
            raise ValueError("Некорректные сетевые правила") from exc
        config.exclusions = exclusions
        config.heuristic_sensitivity = sensitivity
        config.monitored_directory = monitored
        config.network_rules = network_rules
        config.realtime = cls._validate_section(data.get("realtime", {}), DEFAULT_REALTIME,
                                                action="action_on_detection")
        config.quarantine = cls._validate_section(data.get("quarantine", {}), DEFAULT_QUARANTINE)
        config.logging = cls._validate_section(data.get("logging", {}), DEFAULT_LOGGING)
        config.updates = {"public_key": cls._validate_key(data.get("updates", {}).get("public_key", ""))}
        config.behavior_templates = cls._validate_templates(data.get("behavior_templates", []))
        unknown = set(data) - {"modules", "exclusions", "heuristic_sensitivity", "monitored_directory",
                               "network_rules", "realtime", "quarantine", "logging",
                               "behavior_templates", "updates"}
        if unknown:
            raise ValueError(f"Неизвестные параметры конфигурации: {', '.join(sorted(unknown))}")
        return config

    @staticmethod
    def _validate_section(value: dict, defaults: dict, action: str | None = None) -> dict:
        if not isinstance(value, dict):
            raise ValueError("Некорректный раздел конфигурации")
        unknown = set(value) - set(defaults)
        if unknown:
            raise ValueError(f"Неизвестные параметры раздела: {', '.join(sorted(unknown))}")
        merged = defaults.copy()
        merged.update(value)
        for key, item in list(merged.items()):
            if key.endswith("_seconds") or key.startswith("max"):
                _nonnegative_int(item, key)
        if "retention_days" in merged:
            _nonnegative_int(merged["retention_days"], "retention_days")
        if "backup_files" in merged:
            _nonnegative_int(merged["backup_files"], "backup_files")
        if action:
            if merged[action] not in DEFAULT_REALTIME_ACTIONS:
                raise ValueError(f"Действие при обнаружении должно быть одним из {DEFAULT_REALTIME_ACTIONS}")
        return merged

    @staticmethod
    def _validate_key(value: str) -> str:
        if not isinstance(value, str):
            raise ValueError("Публичный ключ обновлений должен быть строкой")
        value = value.strip()
        if value == "":
            return ""
        if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise ValueError("Публичный ключ Ed25519 должен содержать 64 hex-символа")
        return value

    @staticmethod
    def _validate_templates(value: list) -> list:
        if not isinstance(value, list):
            raise ValueError("behavior_templates должен быть списком")
        allowed = {"parent_glob", "child_glob", "name", "risk", "description"}
        for item in value:
            if not isinstance(item, dict) or set(item) - allowed or not {"child_glob", "name", "risk"} <= set(item):
                raise ValueError("Некорректный поведенческий шаблон")
            if item["risk"] not in ("low", "medium", "high"):
                raise ValueError("Риск шаблона должен быть low, medium или high")
        return value

    def save(self, path: str | Path) -> None:
        target = Path(path)
        if target.exists():
            shutil.copy2(target, target.with_suffix(target.suffix + ".bak"))
        from .signatures import atomic_json
        atomic_json(target, asdict(self))
