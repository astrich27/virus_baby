"""Командный интерфейс VirusWall."""

import argparse
import json
from pathlib import Path
import sys

from .core import VirusWall
from .network import list_connections, list_interfaces
from .report import evaluate, export_scan_results


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="viruswall", description="Локальный анализ файлов, процессов и сети")
    p.add_argument("--data-dir", default=str(Path.home() / ".viruswall"))
    commands = p.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    scan = commands.add_parser("scan")
    scan.add_argument("path")
    scan.add_argument("--report", help="Экспорт сводки в .json или .csv")
    sig = commands.add_parser("signature")
    sig.add_argument("action", choices=["add", "remove", "list"])
    sig.add_argument("digest", nargs="?")
    sig.add_argument("name", nargs="?")
    sig.add_argument("--category", default="test")
    commands.add_parser("processes")
    commands.add_parser("connections")
    commands.add_parser("flows")
    commands.add_parser("interfaces")
    capture = commands.add_parser("capture")
    capture.add_argument("interface")
    capture.add_argument("--count", type=int, default=20)
    capture.add_argument("--timeout", type=float, default=5.0)
    watch = commands.add_parser("watch")
    watch.add_argument("directory")
    watch.add_argument("--interval", type=float, default=1.0)
    events = commands.add_parser("events")
    events.add_argument("--type")
    events.add_argument("--source")
    events.add_argument("--severity")
    quarantine = commands.add_parser("quarantine")
    quarantine.add_argument("action", choices=["list", "put", "restore"])
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
    commands.add_parser("gui")
    return p


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        app = VirusWall(args.data_dir)
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
            if args.action == "list":
                output = app.signatures.list()
            elif args.action == "add":
                if not args.digest or not args.name:
                    raise ValueError("Для add нужны SHA-256 и имя")
                app.signatures.add(args.digest, args.name, args.category)
                output = {"added": args.digest}
            else:
                if not args.digest:
                    raise ValueError("Для remove нужен SHA-256")
                output = {"removed": app.signatures.remove(args.digest)}
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
            output = app.journal.read(args.type, args.source, args.severity)
        elif args.command == "quarantine":
            if args.action == "list":
                output = app.quarantine.list()
            elif args.action == "put":
                if not args.item:
                    raise ValueError("Укажите путь к файлу")
                output = app.quarantine_file(args.item, args.name, confirm=args.yes,
                                             remove_original=args.remove_original)
            else:
                if not args.item:
                    raise ValueError("Укажите ID объекта")
                output = {"restored": str(app.restore_file(args.item, confirm=args.yes, target=args.target))}
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
        elif args.command == "gui":
            from .ui import run_desktop
            return run_desktop(app)
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, RuntimeError, PermissionError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
