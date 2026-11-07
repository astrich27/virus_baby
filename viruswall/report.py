"""Оценка результатов сканирования по размеченному тестовому набору."""

import csv
import json
from pathlib import Path
from .models import ScanResult


def evaluate(results: list[ScanResult], known_threats: set[str] | None = None,
             events: list[dict] | None = None) -> dict:
    """known_threats содержит пути действительно вредоносных тестовых объектов."""
    labels = {str(Path(p).absolute()) for p in known_threats} if known_threats is not None else None
    scanned = [r for r in results if r.status in {"clean", "suspicious", "threat"}]
    detected = [r for r in scanned if r.status in {"suspicious", "threat"}]
    true_positive = sum(r.path in labels for r in detected) if labels is not None else None
    false_positive = sum(r.path not in labels for r in detected) if labels is not None else None
    total_threats = sum(r.path in labels for r in scanned) if labels is not None else None
    module_counts = {"signature": sum(any(f.source == "signature" for f in r.findings) for r in results),
                     "heuristic": sum(any(f.source == "heuristic" for f in r.findings) for r in results),
                     "behavior": 0, "filesystem": 0, "network": 0}
    for event in events or []:
        source = event.get("source")
        if source in module_counts and source not in {"signature", "heuristic"}:
            module_counts[source] += 1
    return {"files_scanned": len(scanned), "threats_detected": len(detected),
            "false_positives": false_positive,
            "detection_percent": round(100 * true_positive / total_threats, 2) if total_threats else None,
            "scan_seconds": round(sum(r.elapsed_seconds for r in results), 4),
            "errors": sum(r.status == "error" for r in results),
            "modules": module_counts}


def export_report(report: dict, path: str | Path) -> None:
    target = Path(path)
    if target.suffix.lower() == ".json":
        target.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    elif target.suffix.lower() == ".csv":
        with target.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow(["metric", "value"])
            for key, value in report.items():
                writer.writerow([key, json.dumps(value, ensure_ascii=False)])
    else:
        raise ValueError("Отчёт должен иметь расширение .json или .csv")


def export_scan_results(results: list[ScanResult], path: str | Path) -> None:
    """Экспортировать сводку и все результаты по файлам в JSON или CSV."""
    target = Path(path)
    summary = evaluate(results)
    if target.suffix.lower() == ".json":
        target.write_text(json.dumps({"summary": summary, "results": [r.to_dict() for r in results]},
                                     ensure_ascii=False, indent=2), encoding="utf-8")
    elif target.suffix.lower() == ".csv":
        with target.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow(["metric", "value"])
            for key, value in summary.items():
                writer.writerow([key, json.dumps(value, ensure_ascii=False)])
            writer.writerow([])
            writer.writerow(["path", "name", "sha256", "status", "threat_name", "classification",
                             "scanned_at", "elapsed_seconds", "error", "findings"])
            for item in results:
                writer.writerow([item.path, item.name, item.sha256, item.status, item.threat_name,
                                 item.classification, item.scanned_at, item.elapsed_seconds, item.error,
                                 json.dumps([f.to_dict() for f in item.findings], ensure_ascii=False)])
    else:
        raise ValueError("Отчёт должен иметь расширение .json или .csv")
