"""Потоковое сканирование файлов и каталогов: хэш-сигнатуры (SHA-256/MD5) и байтовые шаблоны."""

import os
from pathlib import Path
from time import monotonic
from collections.abc import Callable, Iterator

from .models import Finding, ScanResult, now_utc
from .signatures import SignatureDatabase, hashes_file
from .config import matches_exclusion

PATTERN_SAMPLE_LIMIT = 2048 * 1024


class FileScanner:
    """Сканер сигнатур с исключениями (пути и маски) и продолжением после ошибок доступа."""

    def __init__(self, signatures: SignatureDatabase | None, exclusions: list[str] | None = None,
                 analyzers: list[Callable[[Path], list[Finding]]] | None = None):
        self.signatures = signatures
        self.exclusions = list(exclusions or [])
        self.analyzers = analyzers or []

    def excluded(self, path: Path) -> bool:
        absolute = path.absolute()
        return matches_exclusion(self.exclusions, absolute)

    def scan_file(self, path: str | Path) -> ScanResult:
        target = Path(path).expanduser().absolute()
        started = monotonic()
        stamp = now_utc()
        md5 = None
        if self.excluded(target):
            return ScanResult(str(target), target.name, None, "excluded", stamp, monotonic() - started)
        if target.is_symlink():
            return ScanResult(str(target), target.name, None, "skipped_symlink", stamp, monotonic() - started)
        try:
            if not target.is_file():
                raise ValueError("Путь не является обычным файлом")
            digest, md5 = hashes_file(target)
            signature = None
            matched_by = None
            if self.signatures:
                signature = self.signatures.lookup(digest)
                matched_by = "sha256"
                if signature is None and md5:
                    signature = self.signatures.lookup_md5(md5)
                    matched_by = "md5"
            findings = []
            if signature:
                findings.append(Finding("signature", signature["name"], "high",
                                        f"Совпадение {matched_by}", digest))
            if self.signatures and not signature:
                with open(target, "rb") as stream:
                    sample = stream.read(min(PATTERN_SAMPLE_LIMIT, os.path.getsize(target) or 1))
                for item in self.signatures.match_sample(sample):
                    findings.append(Finding("signature", item["name"], "high",
                                            "Совпадение байтового шаблона", digest))
                    signature = item
                    break
            for analyzer in self.analyzers:
                findings.extend(analyzer(target))
            threat_name = signature["name"] if signature else findings[0].name if findings else None
            category = signature["category"] if signature else "heuristic" if findings else None
            return ScanResult(str(target), target.name, digest,
                              "threat" if signature else "suspicious" if findings else "clean",
                              stamp, monotonic() - started, threat_name, category, findings)
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
