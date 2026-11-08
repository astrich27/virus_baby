# Публичные интерфейсы модулей

Внешнего сетевого API нет. Python API доступен после `from viruswall.core import VirusWall`:

- `VirusWall(data_dir)` — создать приложение и локальное хранилище (lock-файл, проверка целостности, tamper-события).
- `status() -> dict` — состояние модулей, базы, версии движка/базы, флаг отката из резервной копии.
- `scan_file(path) -> ScanResult`, `scan_directory(path) -> list[ScanResult]` — анализ хешей (SHA-256/MD5), шаблонов и эвристики.
- `watch_directory(path) -> DirectoryMonitor` — резервный мониторинг опросом; `realtime_monitor(path)` — мониторинг на событиях ОС (watchdog) с политиками из `config.realtime`; `arm()`/`disarm()` — управление автокарантином.
- `new_process_findings()` и `network_findings()` — сравнение снимков процессов/соединений; `handle_file_event(event)` — конвейер файловых событий.
- `capture(interface, count=20, timeout=5.0)` — ограниченный пассивный захват; `EventJournal`-подписчики получают `record` (словарь с `event_id`, `prev_hash`, `chain_hash`); `app.network_analyzer.analyze_pcap(path, limit)` — разбор сохранённого захвата.
- `quarantine_file(path, threat_name, confirm=True, remove_original=False)` — зашифрованная копия; `restore_file(item_id, confirm=True, target=None, rescan=True)` — восстановление с повторным сканированием; `delete_quarantine_item(item_id, confirm=True, wipe_passes=3)` — безопасное удаление с перезаписью; `purge_quarantine(confirm=True)` — удаление объектов старше срока хранения. Превышение лимитов порождает `QuarantineExceeded` и событие `quarantine_limit`.
- `add_exclusion(path)` — исключение (путь или маска `*.pdf.exe`); `save_config()` — сохранение с_SCHEMA-валидацией и резервной копией `config.json.bak`.

`SignatureDatabase(path)`: `add(sha256, name, category, md5=None)`, `add_pattern(hex, name, category)`, `remove_pattern(name)`, `remove(sha256)`, `update(entries)`, `lookup(sha256)`, `lookup_md5(md5)`, `match_sample(bytes)`, `list()`, `list_patterns()`, `database_version`; автоматический откат из `*.backup.json` при повреждении (`recovered_from_backup`). `HeuristicAnalyzer(sensitivity).analyze(path) -> list[Finding]`. `ProcessMonitor(provider, templates)` — шаблоны из конфигурации (default: офисные цепочки). `NetworkAnalyzer(rules).analyze_connection/.analyze_packet` и `NetworkRules`.

`EventJournal(path, logging_settings)`: `append(event)` возвращает запись со служебными полями; `read(type, source, severity, limit)`; `verify() -> dict` — проверка хеш-цепочки; ротация по `logging.rotation_mb` и срок хранения `retention_days`. `Quarantine(root, quarantine_settings)` — лимиты `max_total_bytes`/`max_items`/`retention_days`. `Updater(core)`: `verify_file(path)` — проверка подписи Ed25519; `apply_file(path)` — атомарное применение с откатом; `updates.generate_keypair()/sign_manifest()` — служебные функции администратора. `selfprotect.doctor(core)` — отчёт самотестирования.

`ScanResult.to_dict()`, `Finding.to_dict()` и `SecurityEvent.to_dict()` — сериализуемые словари. `evaluate(results, known_threats=None, events=None)` возвращает метрики; `export_report(report, path)` экспортирует сводку в **JSON/CSV/TXT**, `export_scan_results(results, path)` — сводку и построчные результаты (JSON/CSV/TXT). Без размеченного набора ложные срабатывания и процент обнаружения остаются `None`.
