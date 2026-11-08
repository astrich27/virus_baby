"""Командный интерфейс VirusWall."""

import argparse
import json
from pathlib import Path
import sys

from .core import VirusWall
from .network import list_connections, list_interfaces
from .report import evaluate, export_scan_results


def _print_row(item: dict) -> None:
    print(json.dumps(item.to_dict(), ensure_ascii=False))


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="viruswall", description="Локальный анализ файлов, процессов и сети")
    p.add_argument("--data-dir", default=str(Path.home() / ".viruswall"))
    commands = p.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    scan = commands.add_parser("scan")
    scan.add_argument("path")
    scan.add_argument("--report", help="Экспорт сводки в .json, .csv или .txt")
    sig = commands.add_parser("signature")
    sig.add_argument("action", choices=["add", "remove", "list", "add-pattern", "remove-pattern"])
    sig.add_argument("digest", nargs="?")
    sig.add_argument("name", nargs="?")
    sig.add_argument("--category", default="test")
    sig.add_argument("--md5", default=None, help="MD5-сумма для хеш-сигнатуры")
    commands.add_parser("processes")
    commands.add_parser("connections")
    commands.add_parser("flows")
    commands.add_parser("interfaces")
    capture = commands.add_parser("capture")
    capture.add_argument("interface")
    capture.add_argument("--count", type=int, default=20)
    capture.add_argument("--timeout", type=float, default=5.0)
    pcap = commands.add_parser("pcap")
    pcap.add_argument("file")
    pcap.add_argument("--limit", type=int, default=10000)
    realtime = commands.add_parser("realtime")
    realtime.add_argument("directory")
    realtime.add_argument("--arm", action="store_true", help="Разрешить автоматический карантин по политике")
    watch = commands.add_parser("watch")
    watch.add_argument("directory")
    watch.add_argument("--interval", type=float, default=1.0)
    events = commands.add_parser("events")
    events.add_argument("--type")
    events.add_argument("--source")
    events.add_argument("--severity")
    events.add_argument("--verify", action="store_true", help="Проверить хеш-цепочку журнала")
    quarantine = commands.add_parser("quarantine")
    quarantine.add_argument("action", choices=["list", "put", "restore", "delete", "purge"])
    quarantine.add_argument("item", nargs="?")
    quarantine.add_argument("--name", default="Manual.Suspicious")
    quarantine.add_argument("--yes", action="store_true", help="Явное подтверждение действия")
    quarantine.add_argument("--remove-original", action="store_true")
    quarantine.add_argument("--target")
    exclude = commands.add_parser("exclude")
    exclude.add_argument("path")
    module = commands.add_parser("module")
    module.add_argument("name")
    module.add_argument("state", choices=["on", "off"])
    sensitivity = commands.add_parser("sensitivity")
    sensitivity.add_argument("value", type=int)
    update = commands.add_parser("update")
    update.add_argument("manifest", help="Файл подписанного манифеста обновления")
    commands.add_parser("doctor")
    commands.add_parser("gui")
    return p


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        app = VirusWall(args.data_dir)
        from .quarantine import QuarantineExceeded
        from .updates import Updater, UpdateError
        output = None
        if args.command == "status":
            output = app.status()
        elif args.command == "scan":
            path = Path(args.path)
            results = app.scan_directory(path) if path.is_dir() else [app.scan_file(path)]
            output = {"results": [r.to_dict() for r in results], "summary": evaluate(results)}
            if args.report:
                export_scan_results(results, args.report)
        elif args.command == "signature":
            output = _signature_command(app, args)
        elif args.command == "processes":
            output = [p.to_dict() for p in app.process_monitor.snapshot()]
        elif args.command == "connections":
            output = [c.to_dict() for c in list_connections()]
        elif args.command == "flows":
            output = app.network_analyzer.flows()
        elif args.command == "interfaces":
            output = list_interfaces()
        elif args.command == "capture":
            output = [{"packet": p.to_dict(), "findings": [f.to_dict() for f in fs]}
                      for p, fs in app.capture(args.interface, args.count, args.timeout)]
        elif args.command == "pcap":
            from .models import SecurityEvent
            analysis = app.network_analyzer.analyze_pcap(args.file, limit=args.limit)
            for entry in analysis["suspicious"]:
                app.journal.append(SecurityEvent(
                    "packet", "network", entry["packet"]["destination_ip"],
                    entry["findings"][0]["name"], entry["findings"][0]["risk"],
                    "notify", "detected", details={"pcap": args.file, "entry": entry}))
            output = analysis
        elif args.command == "realtime":
            monitor = app.realtime_monitor(args.directory)
            if args.arm:
                monitor.arm()
            print(f"Защита {args.directory}; backend: {monitor.backend}; Ctrl+C для остановки", file=sys.stderr)
            monitor.start()
            try:
                import time
                while True:
                    time.sleep(3600)
            except KeyboardInterrupt:
                return 0
            finally:
                monitor.stop()
        elif args.command == "watch":
            monitor = app.watch_directory(args.directory)
            print(f"Мониторинг {args.directory}; Ctrl+C для остановки", file=sys.stderr)
            try:
                while True:
                    for event in monitor.poll():
                        print(json.dumps(event.to_dict(), ensure_ascii=False), flush=True)
                    import time
                    time.sleep(args.interval)
            except KeyboardInterrupt:
                return 0
        elif args.command == "events":
            if args.verify:
                output = app.journal.verify()
            else:
                output = app.journal.read(args.type, args.source, args.severity)
        elif args.command == "quarantine":
            output = _quarantine_command(app, args)
        elif args.command == "exclude":
            app.add_exclusion(args.path)
            output = {"exclusions": app.config.exclusions}
        elif args.command == "module":
            if args.name not in app.config.modules:
                raise ValueError("Неизвестный модуль")
            app.config.modules[args.name] = args.state == "on"
            app.save_config()
            output = {"modules": app.config.modules}
        elif args.command == "sensitivity":
            if not 0 <= args.value <= 100:
                raise ValueError("Диапазон чувствительности: 0–100")
            app.config.heuristic_sensitivity = args.value
            app.save_config()
            output = {"heuristic_sensitivity": args.value}
        elif args.command == "update":
            output = Updater(app).apply_file(args.manifest)
        elif args.command == "doctor":
            from .selfprotect import doctor as run_doctor
            output = run_doctor(app)
        elif args.command == "gui":
            from .ui import run_desktop
            return run_desktop(app)
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, RuntimeError, PermissionError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1


def _signature_command(app, args):
    if args.action == "list":
        return {"signatures": app.signatures.list(), "patterns": app.signatures.list_patterns()}
    if args.action == "add":
        if not args.digest or not args.name:
            raise ValueError("Для add нужны SHA-256 и имя")
        app.signatures.add(args.digest, args.name, args.category, md5=args.md5)
        return {"added": args.digest}
    if args.action == "remove":
        if not args.digest:
            raise ValueError("Для remove нужен SHA-256")
        return {"removed": app.signatures.remove(args.digest)}
    if args.action == "add-pattern":
        if not args.digest or not args.name:
            raise ValueError("Для add-pattern нужны hex-шаблон и имя")
        app.signatures.add_pattern(args.digest, args.name, args.category)
        return {"added_pattern": args.name}
    if not args.name:
        raise ValueError("Для remove-pattern нужно имя шаблона")
    return {"removed_pattern": app.signatures.remove_pattern(args.name)}


def _quarantine_command(app, args):
    if args.action == "list":
        return app.quarantine.list()
    if args.action == "put":
        if not args.item:
            raise ValueError("Укажите путь к файлу")
        return app.quarantine_file(args.item, args.name, confirm=args.yes,
                                   remove_original=args.remove_original)
    if args.action == "restore":
        if not args.item:
            raise ValueError("Укажите ID объекта")
        return {"restored": str(app.restore_file(args.item, confirm=args.yes, target=args.target))}
    if args.action == "delete":
        if not args.item:
            raise ValueError("Укажите ID объекта")
        return {"deleted": app.delete_quarantine_item(args.item, confirm=args.yes)}
    if not args.yes:
        raise ValueError("Обслуживание карантина требует подтверждения (--yes)")
    return {"purged": app.purge_quarantine(confirm=True)}


if __name__ == "__main__":
    raise SystemExit(main())
