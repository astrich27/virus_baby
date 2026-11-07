"""Статический эвристический анализ файлов; не исполняет исследуемый код."""

from collections import Counter
import math
import os
from pathlib import Path

from .models import Finding


MAGIC = {".exe": b"MZ", ".dll": b"MZ", ".elf": b"\x7fELF", ".pdf": b"%PDF", ".zip": b"PK\x03\x04"}
RISKY_EXTENSIONS = {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".sh"}
DECEPTIVE_SUFFIXES = {".pdf", ".jpg", ".jpeg", ".png", ".doc", ".docx", ".txt"}
TOKENS = (b"powershell -enc", b"frombase64string", b"eval(base64", b"curl | sh", b"wget | sh")


class HeuristicAnalyzer:
    """Возвращает сработавшие правила и оценку риска файла."""

    def __init__(self, sensitivity: int = 50, max_sample: int = 1024 * 1024):
        if not 0 <= sensitivity <= 100:
            raise ValueError("Чувствительность должна быть от 0 до 100")
        self.sensitivity = sensitivity
        self.max_sample = max_sample

    @property
    def threshold(self) -> int:
        return max(25, 85 - self.sensitivity // 2)

    def analyze(self, path: Path) -> list[Finding]:
        """Прочитать не более max_sample байт и вернуть правила, прошедшие порог."""
        with open(path, "rb") as stream:
            sample = stream.read(self.max_sample)
        suffix = path.suffix.lower()
        suffixes = [item.lower() for item in path.suffixes]
        rules: list[tuple[str, str, int]] = []
        if suffix in RISKY_EXTENSIONS:
            rules.append(("risky_extension", "Исполняемый или скриптовый тип файла", 15))
        if len(suffixes) >= 2 and suffix in RISKY_EXTENSIONS and suffixes[-2] in DECEPTIVE_SUFFIXES:
            rules.append(("double_extension", "Маскирующее двойное расширение", 55))
        expected = MAGIC.get(suffix)
        if expected and not sample.startswith(expected):
            rules.append(("magic_mismatch", "Расширение не соответствует заголовку файла", 45))
        if sample.startswith(b"MZ") and suffix not in {".exe", ".dll", ".sys"}:
            rules.append(("pe_disguised", "Исполняемый PE под другим расширением", 55))
        if sample.startswith(b"\x7fELF") and suffix not in {".elf", "", ".so"}:
            rules.append(("elf_disguised", "Исполняемый ELF под другим расширением", 55))
        lowered = sample.lower()
        if any(token in lowered for token in TOKENS):
            rules.append(("dangerous_construct", "Подозрительная команда или декодирование", 45))
        if len(sample) >= 2048 and self._entropy(sample) >= 7.6 and suffix in RISKY_EXTENSIONS:
            rules.append(("packed_content", "Высокая энтропия исполняемого файла", 25))
        if os.name != "nt" and path.stat().st_mode & 0o111 and suffix in DECEPTIVE_SUFFIXES:
            rules.append(("executable_document", "Документ помечен как исполняемый", 35))
        score = min(100, sum(weight for _, _, weight in rules))
        if score < self.threshold:
            return []
        risk = "high" if score >= 75 else "medium" if score >= 50 else "low"
        return [Finding("heuristic", "Heuristic.Suspicious", risk, f"Риск {score}/100: {description}", rule)
                for rule, description, _ in rules]

    @staticmethod
    def _entropy(data: bytes) -> float:
        counts = Counter(data)
        length = len(data)
        return -sum((n / length) * math.log2(n / length) for n in counts.values()) if length else 0.0
