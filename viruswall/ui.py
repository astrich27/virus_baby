"""Нативное desktop-окно VirusWall на Qt Widgets."""

from pathlib import Path
import signal
import sys
import threading

from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFileDialog, QFormLayout, QGroupBox,
    QHBoxLayout, QLabel, QLineEdit, QListWidget, QMainWindow, QMessageBox,
    QProgressBar, QPushButton, QSpinBox, QTabWidget, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from .core import VirusWall
from .network import list_connections, list_interfaces
from .report import evaluate, export_scan_results
from .signatures import sha256_file


STYLE = """
QWidget {font-size: 13px; color: #243447; background: #f4f7fb;}
QTabWidget::pane, QGroupBox, QTableWidget, QListWidget {background: white; border: 1px solid #d8e2ef; border-radius: 7px;}
QTabBar::tab {background: #e7eef8; padding: 9px 15px; margin-right: 3px;}
QTabBar::tab:selected {background: #1764b5; color: white;}
QPushButton {background: #1764b5; color: white; border: 0; border-radius: 5px; padding: 7px 12px;}
QPushButton:disabled {background: #9aaabd;}
QLineEdit, QComboBox, QSpinBox {background: white; border: 1px solid #c5d0dd; border-radius: 5px; padding: 5px;}
QHeaderView::section {background: #eaf0f7; padding: 5px; border: 0;}
QGroupBox {font-weight: 600; margin-top: 12px; padding: 10px;}
QGroupBox::title {subcontrol-origin: margin; left: 10px; padding: 0 5px;}
"""


def make_table(headers: list[str]) -> QTableWidget:
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    table.setAlternatingRowColors(True)
    table.horizontalHeader().setStretchLastSection(True)
    table.verticalHeader().setVisible(False)
    return table


def fill_table(table: QTableWidget, rows) -> None:
    rows = list(rows)
    table.setRowCount(len(rows))
    for row_no, row in enumerate(rows):
        for col_no, value in enumerate(row):
            item = QTableWidgetItem("" if value is None else str(value))
            item.setToolTip(item.text())
            table.setItem(row_no, col_no, item)
    table.resizeColumnsToContents()


class ScanWorker(QThread):
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, app: VirusWall, path: Path, parent=None):
        super().__init__(parent)
        self.app = app
        self.path = path

    def run(self) -> None:
        try:
            results = self.app.scan_directory(self.path) if self.path.is_dir() else [self.app.scan_file(self.path)]
            self.completed.emit(results)
        except Exception as exc:
            self.failed.emit(str(exc))


class CaptureWorker(QThread):
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, app: VirusWall, interface: str, parent=None):
        super().__init__(parent)
        self.app = app
        self.interface = interface

    def run(self) -> None:
        try:
            self.completed.emit(self.app.capture(self.interface, count=20, timeout=5.0))
        except Exception as exc:
            self.failed.emit(str(exc))


class VirusWallWindow(QMainWindow):
    """Главное окно с вкладками анализа, журнала, карантина и настроек."""

    def __init__(self, app: VirusWall):
        super().__init__()
        self.app = app
        self.results = []
        self._scan_worker = None
        self._capture_worker = None
        self._watch_stop = None
        self._watch_thread = None
        self._watch_path = ""
        self._background_stop = threading.Event()
        self.setWindowTitle("VirusWall — антивирусный анализатор")
        self.resize(1180, 780)
        self.setStyleSheet(STYLE)
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self._build_dashboard()
        self._build_scanner()
        self._build_heuristic()
        self._build_processes()
        self._build_network()
        self._build_journal()
        self._build_quarantine()
        self._build_settings()
        self._refresh_dashboard()
        self._refresh_journal()
        self._refresh_quarantine()
        self._refresh_signatures()
        self._refresh_processes()
        self._refresh_network()
        self._background_thread = threading.Thread(target=self.app.run_background,
                                                   args=(self._background_stop,), daemon=True)
        self._background_thread.start()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._periodic_refresh)
        self.timer.start(5000)
        self.statusBar().showMessage("Готово. Сканирование и мониторинг работают локально.")

    def _new_tab(self, title: str) -> QVBoxLayout:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)
        self.tabs.addTab(widget, title)
        return layout

    def _build_dashboard(self) -> None:
        layout = self._new_tab("Главная")
        heading = QLabel("Состояние VirusWall")
        heading.setStyleSheet("font-size: 22px; font-weight: 700; color: #17365c")
        layout.addWidget(heading)
        layout.addWidget(QLabel("Учебный анализатор: сканирование по запросу и пассивный мониторинг."))
        self.status_label = QLabel()
        layout.addWidget(self.status_label)
        self.errors_label = QLabel()
        self.errors_label.setWordWrap(True)
        layout.addWidget(self.errors_label)
        self.quick_button = QPushButton("Быстрое сканирование")
        self.quick_button.clicked.connect(self._quick_scan)
        layout.addWidget(self.quick_button, alignment=Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(QLabel("Последние обнаружения"))
        self.threat_table = make_table(["Время", "Источник", "Объект", "Угроза", "Риск"])
        layout.addWidget(self.threat_table)

    def _build_scanner(self) -> None:
        layout = self._new_tab("Сканирование")
        row = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("Выберите файл или каталог")
        row.addWidget(self.path_edit)
        file_button = QPushButton("Файл…")
        file_button.clicked.connect(self._choose_file)
        row.addWidget(file_button)
        dir_button = QPushButton("Каталог…")
        dir_button.clicked.connect(self._choose_directory)
        row.addWidget(dir_button)
        self.scan_button = QPushButton("Сканировать")
        self.scan_button.clicked.connect(self._scan_selected)
        row.addWidget(self.scan_button)
        layout.addLayout(row)
        self.scan_progress = QProgressBar()
        self.scan_progress.hide()
        layout.addWidget(self.scan_progress)
        self.scan_summary = QLabel("Выберите объект для проверки.")
        layout.addWidget(self.scan_summary)
        self.scan_table = make_table(["Путь", "SHA-256", "Результат", "Угроза", "Время"])
        layout.addWidget(self.scan_table)
        self.export_button = QPushButton("Экспорт отчёта JSON/CSV…")
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self._export_report)
        layout.addWidget(self.export_button, alignment=Qt.AlignmentFlag.AlignLeft)

    def _build_heuristic(self) -> None:
        layout = self._new_tab("Эвристика")
        layout.addWidget(QLabel("Эвристика учитывает формат, расширение, подозрительные строки и признаки упаковки."))
        self.heuristic_label = QLabel()
        layout.addWidget(self.heuristic_label)
        self.heuristic_table = make_table(["Файл", "Правило", "Описание", "Риск"])
        layout.addWidget(self.heuristic_table)

    def _build_processes(self) -> None:
        layout = self._new_tab("Процессы")
        row = QHBoxLayout()
        self.process_label = QLabel("Список процессов")
        row.addWidget(self.process_label)
        row.addStretch()
        button = QPushButton("Обновить")
        button.clicked.connect(self._refresh_processes)
        row.addWidget(button)
        layout.addLayout(row)
        self.process_table = make_table(["PID", "Имя", "Исполняемый файл", "Подозрительные признаки"])
        layout.addWidget(self.process_table)

    def _build_network(self) -> None:
        layout = self._new_tab("Сеть")
        row = QHBoxLayout()
        self.network_label = QLabel("Пассивное наблюдение")
        row.addWidget(self.network_label)
        row.addStretch()
        self.interface_combo = QComboBox()
        row.addWidget(self.interface_combo)
        refresh = QPushButton("Обновить")
        refresh.clicked.connect(self._refresh_network)
        row.addWidget(refresh)
        self.capture_button = QPushButton("Захватить 20 пакетов")
        self.capture_button.clicked.connect(self._start_capture)
        row.addWidget(self.capture_button)
        layout.addLayout(row)
        self.connection_table = make_table(["Протокол", "Локальный адрес", "Удалённый адрес", "Состояние", "PID", "Направление"])
        layout.addWidget(self.connection_table)
        layout.addWidget(QLabel("Последний захват пакетов"))
        self.packet_table = make_table(["Время", "Источник", "Назначение", "Протокол", "DNS", "Правило"])
        layout.addWidget(self.packet_table)

    def _build_journal(self) -> None:
        layout = self._new_tab("Журнал")
        row = QHBoxLayout()
        self.source_filter = QLineEdit()
        self.source_filter.setPlaceholderText("Источник (необязательно)")
        row.addWidget(self.source_filter)
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["Все уровни", "low", "medium", "high"])
        row.addWidget(self.severity_filter)
        button = QPushButton("Фильтровать")
        button.clicked.connect(self._refresh_journal)
        row.addWidget(button)
        layout.addLayout(row)
        self.event_table = make_table(["Время", "Тип", "Источник", "Объект", "Угроза", "Риск", "Действие", "Результат"])
        layout.addWidget(self.event_table)

    def _build_quarantine(self) -> None:
        layout = self._new_tab("Карантин")
        layout.addWidget(QLabel("Файл помещается только после подтверждения. По умолчанию оригинал остаётся на месте."))
        row = QHBoxLayout()
        self.threat_name_edit = QLineEdit("Manual.Suspicious")
        self.threat_name_edit.setPlaceholderText("Название угрозы")
        row.addWidget(self.threat_name_edit)
        self.remove_original_check = QCheckBox("Изолировать: убрать исходный файл после сохранения копии")
        row.addWidget(self.remove_original_check)
        put_button = QPushButton("Поместить файл…")
        put_button.clicked.connect(self._quarantine_file)
        row.addWidget(put_button)
        layout.addLayout(row)
        self.quarantine_table = make_table(["ID", "Исходный путь", "Угроза", "Дата", "Оригинал убран"])
        layout.addWidget(self.quarantine_table)
        row = QHBoxLayout()
        restore_button = QPushButton("Восстановить выбранный")
        restore_button.clicked.connect(self._restore_file)
        row.addWidget(restore_button)
        refresh_button = QPushButton("Обновить список")
        refresh_button.clicked.connect(self._refresh_quarantine)
        row.addWidget(refresh_button)
        row.addStretch()
        layout.addLayout(row)

    def _build_settings(self) -> None:
        layout = self._new_tab("Настройки")
        module_box = QGroupBox("Модули")
        module_layout = QVBoxLayout(module_box)
        self.module_checks = {}
        for name, enabled in self.app.config.modules.items():
            check = QCheckBox(name)
            check.setChecked(enabled)
            module_layout.addWidget(check)
            self.module_checks[name] = check
        layout.addWidget(module_box)
        form = QFormLayout()
        self.sensitivity_spin = QSpinBox()
        self.sensitivity_spin.setRange(0, 100)
        self.sensitivity_spin.setValue(self.app.config.heuristic_sensitivity)
        form.addRow("Чувствительность эвристики", self.sensitivity_spin)
        layout.addLayout(form)
        save_button = QPushButton("Сохранить настройки")
        save_button.clicked.connect(self._save_settings)
        layout.addWidget(save_button, alignment=Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(QLabel("Исключения"))
        self.exclusion_list = QListWidget()
        self.exclusion_list.addItems(self.app.config.exclusions)
        layout.addWidget(self.exclusion_list)
        row = QHBoxLayout()
        add_button = QPushButton("Добавить путь…")
        add_button.clicked.connect(self._add_exclusion)
        row.addWidget(add_button)
        remove_button = QPushButton("Убрать исключение")
        remove_button.clicked.connect(self._remove_exclusion)
        row.addWidget(remove_button)
        row.addStretch()
        layout.addLayout(row)
        layout.addWidget(QLabel("Контроль файловой системы"))
        self.watch_label = QLabel("Остановлен")
        layout.addWidget(self.watch_label)
        row = QHBoxLayout()
        start_watch = QPushButton("Следить за каталогом…")
        start_watch.clicked.connect(self._start_watch)
        row.addWidget(start_watch)
        stop_watch = QPushButton("Остановить")
        stop_watch.clicked.connect(self._stop_watch)
        row.addWidget(stop_watch)
        row.addStretch()
        layout.addLayout(row)
        layout.addWidget(QLabel("Локальная база сигнатур"))
        self.signature_table = make_table(["SHA-256", "Имя", "Категория"])
        layout.addWidget(self.signature_table)
        row = QHBoxLayout()
        add_signature = QPushButton("Добавить сигнатуру файла…")
        add_signature.clicked.connect(self._add_signature)
        row.addWidget(add_signature)
        remove_signature = QPushButton("Удалить выбранную")
        remove_signature.clicked.connect(self._remove_signature)
        row.addWidget(remove_signature)
        row.addStretch()
        layout.addLayout(row)

    def _notify(self, text: str, warning: bool = False) -> None:
        self.statusBar().showMessage(text, 12000)
        if warning:
            QMessageBox.warning(self, "VirusWall", text)

    def _refresh_dashboard(self) -> None:
        status = self.app.status()
        enabled = sum(status["modules"].values())
        self.status_label.setText(f"Модули: {enabled}/{len(status['modules'])} включено  •  "
                                  f"Сигнатуры: {status['signature_count']}  •  "
                                  f"Карантин: {status['quarantine_count']}")
        errors = status["monitor_errors"]
        self.errors_label.setText("Ограничения ОС: " + "; ".join(f"{key}: {value}" for key, value in errors.items()) if errors else "")
        events = [e for e in self.app.journal.read(limit=100) if e.get("severity") in {"medium", "high"}]
        fill_table(self.threat_table, [(e.get("timestamp"), e.get("source"), e.get("target"),
                                       e.get("threat_name"), e.get("severity")) for e in events[:30]])

    def _choose_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Выберите файл")
        if path:
            self.path_edit.setText(path)

    def _choose_directory(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Выберите каталог")
        if path:
            self.path_edit.setText(path)

    def _quick_scan(self) -> None:
        default = Path.home() / "Downloads"
        self._start_scan(default if default.is_dir() else Path.cwd())

    def _scan_selected(self) -> None:
        text = self.path_edit.text().strip()
        if not text:
            self._notify("Выберите файл или каталог.", warning=True)
            return
        self._start_scan(Path(text).expanduser())

    def _start_scan(self, path: Path) -> None:
        if self._scan_worker and self._scan_worker.isRunning():
            return
        if not path.exists():
            self._notify(f"Путь не найден: {path}", warning=True)
            return
        self.scan_button.setEnabled(False)
        self.quick_button.setEnabled(False)
        self.scan_progress.setRange(0, 0)
        self.scan_progress.show()
        self.scan_summary.setText(f"Проверяется: {path}")
        self._scan_worker = ScanWorker(self.app, path, self)
        self._scan_worker.completed.connect(self._scan_completed)
        self._scan_worker.failed.connect(lambda error: self._notify(f"Ошибка сканирования: {error}", warning=True))
        self._scan_worker.finished.connect(self._scan_finished)
        self._scan_worker.start()

    def _scan_completed(self, results) -> None:
        self.results = results
        summary = evaluate(results)
        self.scan_summary.setText(f"Проверено: {summary['files_scanned']}  •  "
                                  f"Обнаружено: {summary['threats_detected']}  •  "
                                  f"Ошибок: {summary['errors']}  •  {summary['scan_seconds']} с"
                                  + (f"  •  В таблице первые 500 из {len(results)}; экспорт содержит все"
                                     if len(results) > 500 else ""))
        fill_table(self.scan_table, [(r.path, r.sha256, r.status, r.threat_name or r.error, r.scanned_at)
                                     for r in results[:500]])
        self.export_button.setEnabled(True)
        fill_table(self.heuristic_table, [(r.path, f.rule, f.description, f.risk)
                                          for r in results for f in r.findings if f.source == "heuristic"])
        self.heuristic_label.setText(f"Чувствительность: {self.app.config.heuristic_sensitivity}/100")
        self._refresh_dashboard()
        self._refresh_journal()
        if summary["threats_detected"]:
            self._notify(f"Обнаружено подозрительных объектов: {summary['threats_detected']}", warning=True)

    def _scan_finished(self) -> None:
        self.scan_button.setEnabled(True)
        self.quick_button.setEnabled(True)
        self.scan_progress.hide()

    def _export_report(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить отчёт", "viruswall-report.json",
                                              "JSON (*.json);;CSV (*.csv)")
        if path:
            try:
                export_scan_results(self.results, path)
                self._notify(f"Отчёт сохранён: {path}")
            except (OSError, ValueError) as exc:
                self._notify(str(exc), warning=True)

    def _refresh_processes(self) -> None:
        if not self.app.config.modules["behavior"]:
            self.process_label.setText("Модуль процессов отключён")
            fill_table(self.process_table, [])
            return
        try:
            processes = self.app.process_monitor.snapshot()
            rows = []
            for process in processes[:300]:
                findings = self.app.process_monitor.analyze(process, processes)
                rows.append((process.pid, process.name, process.exe,
                             "; ".join(f.description for f in findings)))
            fill_table(self.process_table, rows)
            self.process_label.setText(f"Процессов: {len(processes)}; показаны первые {len(rows)}")
        except (OSError, RuntimeError) as exc:
            self.process_label.setText(f"Данные процессов недоступны: {exc}")
            fill_table(self.process_table, [])

    def _refresh_network(self) -> None:
        try:
            interfaces = list_interfaces()
            selected = self.interface_combo.currentText()
            self.interface_combo.clear()
            self.interface_combo.addItems(interfaces)
            if selected in interfaces:
                self.interface_combo.setCurrentText(selected)
            if not self.app.config.modules["network"]:
                self.network_label.setText("Сетевой модуль отключён")
                fill_table(self.connection_table, [])
                return
            connections = list_connections()
            fill_table(self.connection_table,
                       [(c.protocol, f"{c.local_ip}:{c.local_port}",
                         f"{c.remote_ip}:{c.remote_port}" if c.remote_ip else "",
                         c.state, c.pid, c.direction) for c in connections[:300]])
            self.network_label.setText(f"Соединений: {len(connections)}; направление TCP приблизительное")
        except (OSError, RuntimeError) as exc:
            self.network_label.setText(f"Сетевые сведения недоступны: {exc}")
            fill_table(self.connection_table, [])

    def _start_capture(self) -> None:
        interface = self.interface_combo.currentText()
        if not interface:
            self._notify("Выберите сетевой интерфейс.", warning=True)
            return
        if self._capture_worker and self._capture_worker.isRunning():
            return
        self.capture_button.setEnabled(False)
        self._capture_worker = CaptureWorker(self.app, interface, self)
        self._capture_worker.completed.connect(self._capture_completed)
        self._capture_worker.failed.connect(lambda error: self._notify(f"Захват недоступен: {error}", warning=True))
        self._capture_worker.finished.connect(lambda: self.capture_button.setEnabled(True))
        self._capture_worker.start()

    def _capture_completed(self, packets) -> None:
        fill_table(self.packet_table,
                   [(p.observed_at, f"{p.source_ip}:{p.source_port}",
                     f"{p.destination_ip}:{p.destination_port}", p.protocol, p.dns_query,
                     "; ".join(f.name for f in findings)) for p, findings in packets])
        self._refresh_dashboard()
        self._refresh_journal()
        self._notify(f"Получено пакетов: {len(packets)}")

    def _refresh_journal(self) -> None:
        source = self.source_filter.text().strip() or None
        severity = self.severity_filter.currentText()
        if severity == "Все уровни":
            severity = None
        events = self.app.journal.read(source=source, severity=severity, limit=200)
        fill_table(self.event_table,
                   [(e.get("timestamp"), e.get("event_type"), e.get("source"), e.get("target"),
                     e.get("threat_name"), e.get("severity"), e.get("action"), e.get("outcome")) for e in events])

    def _refresh_quarantine(self) -> None:
        fill_table(self.quarantine_table,
                   [(item.get("id"), item.get("original_path"), item.get("threat_name"),
                     item.get("timestamp"), "да" if item.get("original_removed") else "нет")
                    for item in self.app.quarantine.list()])

    def _quarantine_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Файл для карантина")
        if not path:
            return
        remove_original = self.remove_original_check.isChecked()
        action = "изолировать и убрать исходный файл" if remove_original else "сохранить шифрованную копию"
        if QMessageBox.question(self, "Подтверждение", f"{action.capitalize()}?\n{path}") != QMessageBox.StandardButton.Yes:
            return
        try:
            item = self.app.quarantine_file(path, self.threat_name_edit.text().strip() or "Manual.Suspicious",
                                            confirm=True, remove_original=remove_original)
            self._refresh_quarantine()
            self._refresh_dashboard()
            self._refresh_journal()
            self._notify(f"Объект помещён в карантин: {item['id']}")
        except (OSError, ValueError, RuntimeError) as exc:
            self._notify(str(exc), warning=True)

    def _restore_file(self) -> None:
        row = self.quarantine_table.currentRow()
        if row < 0:
            self._notify("Выберите объект карантина.", warning=True)
            return
        item_id = self.quarantine_table.item(row, 0).text()
        original = Path(self.quarantine_table.item(row, 1).text())
        target = None
        if original.exists():
            target, _ = QFileDialog.getSaveFileName(self, "Исходный путь занят — выберите новый", str(original))
            if not target:
                return
        if QMessageBox.question(self, "Подтверждение", f"Восстановить объект {item_id}?") != QMessageBox.StandardButton.Yes:
            return
        try:
            restored = self.app.restore_file(item_id, confirm=True, target=target)
            self._refresh_journal()
            self._notify(f"Файл восстановлен: {restored}")
        except (OSError, ValueError, RuntimeError) as exc:
            self._notify(str(exc), warning=True)

    def _save_settings(self) -> None:
        self.app.config.modules = {name: checkbox.isChecked() for name, checkbox in self.module_checks.items()}
        self.app.config.heuristic_sensitivity = self.sensitivity_spin.value()
        try:
            self.app.save_config()
            self.heuristic_label.setText(f"Чувствительность: {self.app.config.heuristic_sensitivity}/100")
            self._refresh_dashboard()
            self._notify("Настройки сохранены")
        except (OSError, ValueError) as exc:
            self._notify(str(exc), warning=True)

    def _add_exclusion(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Каталог для исключения")
        if path:
            self.app.add_exclusion(path)
            self.exclusion_list.clear()
            self.exclusion_list.addItems(self.app.config.exclusions)
            self._notify("Исключение добавлено")

    def _remove_exclusion(self) -> None:
        selected = self.exclusion_list.currentItem()
        if selected:
            self.app.config.exclusions.remove(selected.text())
            self.app.save_config()
            self.exclusion_list.takeItem(self.exclusion_list.currentRow())
            self._notify("Исключение удалено")

    def _start_watch(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Каталог для мониторинга")
        if not path:
            return
        self._stop_watch()
        try:
            monitor = self.app.watch_directory(path)
            self._watch_stop = threading.Event()
            self._watch_thread = threading.Thread(target=monitor.run,
                                                  kwargs={"stop": self._watch_stop}, daemon=True)
            self._watch_thread.start()
            self._watch_path = path
            self.watch_label.setText(f"Наблюдение: {path}")
            self._notify("Мониторинг файлов запущен")
        except (OSError, RuntimeError) as exc:
            self._notify(str(exc), warning=True)

    def _stop_watch(self) -> None:
        if self._watch_stop:
            self._watch_stop.set()
        if self._watch_thread:
            self._watch_thread.join(timeout=2)
        self._watch_stop = None
        self._watch_thread = None
        self._watch_path = ""
        self.watch_label.setText("Остановлен")

    def _refresh_signatures(self) -> None:
        fill_table(self.signature_table,
                   [(digest, item["name"], item["category"])
                    for digest, item in self.app.signatures.list().items()])

    def _add_signature(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Файл для тестовой сигнатуры")
        if not path:
            return
        from PySide6.QtWidgets import QInputDialog
        name, accepted = QInputDialog.getText(self, "Название сигнатуры", "Название угрозы:",
                                               text=f"Lab.{Path(path).name}")
        if not accepted or not name.strip():
            return
        try:
            self.app.signatures.add(sha256_file(path), name.strip(), "test")
            self._refresh_signatures()
            self._refresh_dashboard()
            self._notify("Сигнатура добавлена")
        except (OSError, ValueError) as exc:
            self._notify(str(exc), warning=True)

    def _remove_signature(self) -> None:
        row = self.signature_table.currentRow()
        if row < 0:
            return
        digest = self.signature_table.item(row, 0).text()
        if QMessageBox.question(self, "Подтверждение", "Удалить выбранную сигнатуру?") != QMessageBox.StandardButton.Yes:
            return
        self.app.signatures.remove(digest)
        self._refresh_signatures()
        self._refresh_dashboard()

    def _periodic_refresh(self) -> None:
        self._refresh_dashboard()
        self._refresh_journal()
        if self.tabs.currentIndex() == 3:
            self._refresh_processes()
        elif self.tabs.currentIndex() == 4:
            self._refresh_network()
        elif self.tabs.currentIndex() == 6:
            self._refresh_quarantine()

    def closeEvent(self, event) -> None:
        if (self._scan_worker and self._scan_worker.isRunning()) or (
                self._capture_worker and self._capture_worker.isRunning()):
            self._notify("Дождитесь завершения сканирования или захвата пакетов.", warning=True)
            event.ignore()
            return
        self.timer.stop()
        self._stop_watch()
        self._background_stop.set()
        self._background_thread.join(timeout=3)
        event.accept()


def run_desktop(app: VirusWall) -> int:
    """Создать и открыть отдельное окно приложения без веб-сервера."""
    qt_app = QApplication.instance() or QApplication(sys.argv)
    qt_app.setApplicationName("VirusWall")
    window = VirusWallWindow(app)
    window.show()
    previous_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, lambda *_: window.close())
    interrupt_timer = QTimer()
    interrupt_timer.timeout.connect(lambda: None)
    interrupt_timer.start(250)
    try:
        return qt_app.exec()
    finally:
        interrupt_timer.stop()
        signal.signal(signal.SIGINT, previous_sigint)
        window.close()
