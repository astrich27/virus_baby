"""Конфигурация модулей VirusWall."""

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path


DEFAULT_MODULES = {"signatures": True, "heuristic": True, "behavior": True,
                   "filesystem": True, "network": True}


@dataclass
class Config:
    modules: dict[str, bool] = field(default_factory=lambda: DEFAULT_MODULES.copy())
    exclusions: list[str] = field(default_factory=list)
    heuristic_sensitivity: int = 50
    monitored_directory: str = ""
    network_rules: dict = field(default_factory=dict)

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
        return config

    def save(self, path: str | Path) -> None:
        from .signatures import atomic_json
        atomic_json(Path(path), asdict(self))
