"""Потоковое сканирование файлов и каталогов."""

import os
from pathlib import Path
from time import monotonic
from collections.abc import Callable, Iterator

from .models import Finding, ScanResult, now_utc
from .signatures import SignatureDatabase, sha256_file


class FileScanner:
    """Сканер SHA-256 с исключениями и продолжением после ошибок доступа."""

    def __init__(self, signatures: SignatureDatabase | None, exclusions: list[str] | None = None,
                 analyzers: list[Callable[[Path], list[Finding]]] | None = None):
        self.signatures = signatures
        self.exclusions = [Path(item).expanduser().absolute() for item in (exclusions or [])]
        self.analyzers = analyzers or []

    def excluded(self, path: Path) -> bool:
        absolute = path.absolute()
        return any(absolute == root or root in absolute.parents for root in self.exclusions)

    def scan_file(self, path: str | Path) -> ScanResult:
        target = Path(path).expanduser().absolute()
        started = monotonic()
        stamp = now_utc()
        if self.excluded(target):
            return ScanResult(str(target), target.name, None, "excluded", stamp, monotonic() - started)
        if target.is_symlink():
            return ScanResult(str(target), target.name, None, "skipped_symlink", stamp, monotonic() - started)
        try:
            if not target.is_file():
                raise ValueError("Путь не является обычным файлом")
            digest = sha256_file(target)
            signature = self.signatures.lookup(digest) if self.signatures else None
            findings = []
            if signature:
                findings.append(Finding("signature", signature["name"], "high", "Совпадение SHA-256", digest))
            for analyzer in self.analyzers:
                findings.extend(analyzer(target))
            return ScanResult(str(target), target.name, digest,
                              "threat" if signature else "suspicious" if findings else "clean",
                              stamp, monotonic() - started,
                              signature["name"] if signature else findings[0].name if findings else None,
                              signature["category"] if signature else "heuristic" if findings else None,
                              findings)
        except (OSError, ValueError) as exc:
            return ScanResult(str(target), target.name, None, "error", stamp,
                              monotonic() - started, error=str(exc))

    def scan_directory(self, directory: str | Path) -> Iterator[ScanResult]:
        root = Path(directory).expanduser().absolute()
        if not root.is_dir():
            raise NotADirectoryError(str(root))
        def onerror(error: OSError) -> None:
            errors.append(error)
        errors: list[OSError] = []
        for base, dirs, files in os.walk(root, followlinks=False, onerror=onerror):
            base_path = Path(base)
            dirs[:] = sorted(d for d in dirs if not self.excluded(base_path / d) and not (base_path / d).is_symlink())
            for name in sorted(files):
                yield self.scan_file(base_path / name)
            while errors:
                error = errors.pop(0)
                path = Path(error.filename or base)
                yield ScanResult(str(path), path.name, None, "error", now_utc(), 0.0, error=str(error))
