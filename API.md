# Публичные интерфейсы модулей

Внешнего сетевого API нет. Python API доступен после `from viruswall.core import VirusWall`:

- `VirusWall(data_dir)` — создать приложение и локальное хранилище.
- `status() -> dict` — состояние модулей и базы.
- `scan_file(path) -> ScanResult`, `scan_directory(path) -> list[ScanResult]` — анализ файлов.
- `watch_directory(path) -> DirectoryMonitor` — создать монитор; `poll()` возвращает события и передаёт их ядру.
- `new_process_findings()` и `network_findings()` — сравнить снимки процессов/соединений и вернуть обнаружения.
- `capture(interface, count=20, timeout=5.0)` — ограниченный пассивный захват пакетов.
- `quarantine_file(path, threat_name, confirm=True, remove_original=False)` — зашифровать копию; исходный файл удаляется только при отдельном флаге.
- `restore_file(item_id, confirm=True, target=None)` — восстановить без перезаписи существующего файла.
- `add_exclusion(path)` — сохранить исключение.

`SignatureDatabase(path)` предоставляет `add(sha256, name, category)`, `remove(sha256)`, `update(entries)`, `lookup(sha256)` и `list()`. `HeuristicAnalyzer(sensitivity).analyze(path)` возвращает список `Finding`. `ProcessMonitor.snapshot()` возвращает `ProcessInfo`; `new_processes()` отслеживает новые объекты по PID и времени запуска. `NetworkAnalyzer(rules).analyze_connection(info)` и `.analyze_packet(info)` возвращают находки правил. `EventJournal(path).read(event_type=None, source=None, severity=None, limit=200)` фильтрует историю.

`ScanResult.to_dict()`, `Finding.to_dict()` и `SecurityEvent.to_dict()` дают сериализуемые словари. `evaluate(results, known_threats=None, events=None)` возвращает метрики; `export_report(report, path)` экспортирует сводку, а `export_scan_results(results, path)` — сводку и все построчные результаты в JSON или CSV. `known_threats` — множество полных путей размеченных тестовых угроз. Без него показатели ложных срабатываний и процента обнаружения остаются `None`. Для подсчёта событий поведения, файловой системы и сети передайте список записей журнала в `events`.
