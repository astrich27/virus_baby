"""Пассивный анализ списка процессов; шаблоны поведения настраиваются конфигурацией."""

from dataclasses import asdict, dataclass
from fnmatch import fnmatch
from pathlib import Path
import os
import tempfile

from .models import Finding, now_utc


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    ppid: int | None
    name: str
    exe: str | None
    created_at: float | None
    observed_at: str

    def to_dict(self):
        return asdict(self)


DEFAULT_TEMPLATES = (
    {"parent_glob": "winword.exe", "child_glob": "powershell.exe", "name": "Process.OfficeShellChild",
     "risk": "high", "description": "Офисное приложение запустило оболочку"},
    {"parent_glob": "winword.exe", "child_glob": "cmd.exe", "name": "Process.OfficeShellChild",
     "risk": "high", "description": "Офисное приложение запустило оболочку"},
    {"parent_glob": "excel.exe", "child_glob": "powershell.exe", "name": "Process.OfficeShellChild",
     "risk": "high", "description": "Офисное приложение запустило оболочку"},
    {"parent_glob": "excel.exe", "child_glob": "cmd.exe", "name": "Process.OfficeShellChild",
     "risk": "high", "description": "Офисное приложение запустило оболочку"},
    {"parent_glob": "soffice.bin", "child_glob": "powershell.exe", "name": "Process.OfficeShellChild",
     "risk": "high", "description": "Офисное приложение запустило оболочку"},
    {"parent_glob": "soffice.bin", "child_glob": "cmd.exe", "name": "Process.OfficeShellChild",
     "risk": "high", "description": "Офисное приложение запустило оболочку"},
    {"parent_glob": "wscript.exe", "child_glob": "powershell.exe", "name": "Process.ScriptShellChild",
     "risk": "medium", "description": "Скриптовый интерпретатор запустил оболочку"},
    {"parent_glob": "cscript.exe", "child_glob": "powershell.exe", "name": "Process.ScriptShellChild",
     "risk": "medium", "description": "Скриптовый интерпретатор запустил оболочку"},
    {"parent_glob": "*.doc*", "child_glob": "*", "name": "Process.DocumentChild",
     "risk": "medium", "description": "Документ создал процесс-потомок"},
)

TEMP_DIRECTORIES = (tempfile.gettempdir(),)


class ProcessMonitor:
    """Снимает снимки процессов через psutil и сравнивает по (pid, start time)."""

    def __init__(self, provider=None, templates: list[dict] | None = None):
        self.provider = provider or self._system_provider
        self.templates = templates if templates is not None else list(DEFAULT_TEMPLATES)
        self._previous: dict[tuple[int, float | None], ProcessInfo] | None = None

    @staticmethod
    def _system_provider() -> list[ProcessInfo]:
        try:
            import psutil
        except ImportError as exc:
            raise RuntimeError("Для мониторинга процессов установите psutil") from exc
        found = []
        try:
            for process in psutil.process_iter(["pid", "ppid", "name", "exe", "create_time"]):
                try:
                    info = process.info
                    found.append(ProcessInfo(info["pid"], info.get("ppid"), info.get("name") or "",
                                             info.get("exe"), info.get("create_time"), now_utc()))
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    continue
        except (psutil.AccessDenied, PermissionError) as exc:
            raise PermissionError("ОС запретила просмотр списка процессов") from exc
        return found

    def snapshot(self) -> list[ProcessInfo]:
        return self.provider()

    def new_processes(self) -> list[ProcessInfo]:
        new, _ = self.update_snapshot()
        return new

    def update_snapshot(self) -> tuple[list[ProcessInfo], list[ProcessInfo]]:
        """Вернуть новые процессы и полный текущий снимок."""
        current = self.snapshot()
        keyed = {(item.pid, item.created_at): item for item in current}
        new = [] if self._previous is None else [item for key, item in keyed.items() if key not in self._previous]
        self._previous = keyed
        return new, current

    def analyze(self, process: ProcessInfo, processes: list[ProcessInfo] | None = None) -> list[Finding]:
        findings = []
        exe = process.exe or ""
        if exe:
            try:
                path = Path(exe).resolve(strict=False)
                for temp in TEMP_DIRECTORIES:
                    temp_path = Path(temp).resolve()
                    if temp_path == path or temp_path in path.parents:
                        findings.append(Finding("behavior", "Process.TempExecutable", "medium",
                                                "Исполняемый файл запущен из временного каталога",
                                                "temp_executable"))
                        break
            except (OSError, RuntimeError):
                pass
        if processes and process.ppid:
            parent = next((item for item in processes if item.pid == process.ppid), None)
            if parent:
                findings.extend(self._match_templates(parent.name, process.name))
        return findings

    def _match_templates(self, parent_name: str, child_name: str) -> list[Finding]:
        found = []
        parent_fc, child_fc = parent_name.lower(), child_name.lower()
        for template in self.templates:
            parent_glob = str(template.get("parent_glob", "*")).lower()
            child_glob = str(template.get("child_glob", "*")).lower()
            if (fnmatch(parent_fc, parent_glob) or fnmatch(parent_name, template.get("parent_glob", "*"))) \
                    and (fnmatch(child_fc, child_glob) or fnmatch(child_name, template.get("child_glob", "*"))):
                found.append(Finding("behavior", template["name"], template["risk"],
                                     template.get("description", "Совпадение поведенческого шаблона"),
                                     "behavior_template"))
        return found

