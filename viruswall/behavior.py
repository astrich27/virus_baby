"""Пассивный анализ списка процессов; не вмешивается в процессы."""

from dataclasses import asdict, dataclass
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


class ProcessMonitor:
    """Снимает снимки процессов через psutil и сравнивает по (pid, start time)."""

    def __init__(self, provider=None):
        self.provider = provider or self._system_provider
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
                temp = Path(tempfile.gettempdir()).resolve()
                if temp == path or temp in path.parents:
                    findings.append(Finding("behavior", "Process.TempExecutable", "medium",
                                            "Исполняемый файл запущен из временного каталога", "temp_executable"))
            except (OSError, RuntimeError):
                pass
        if processes and process.ppid:
            parent = next((item for item in processes if item.pid == process.ppid), None)
            if parent and parent.name.lower() in {"winword.exe", "excel.exe", "soffice.bin"} and process.name.lower() in {"powershell.exe", "cmd.exe", "sh", "bash"}:
                findings.append(Finding("behavior", "Process.OfficeShellChild", "high",
                                        "Офисное приложение запустило оболочку", "office_shell_child"))
        return findings
