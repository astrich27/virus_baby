"""Нативное desktop-окно VirusWall на Qt Widgets.

Современный интерфейс: две темы (светлая/тёмная с переключателем), подсказки
ко всем элементам, контекстные меню по правой кнопке мыши и краткие
инструкции на каждой вкладке.
"""

import json
from pathlib import Path
import signal
import sys
import threading

from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtGui import QColor, QGuiApplication
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFileDialog, QFormLayout, QGroupBox,
    QHBoxLayout, QLabel, QLineEdit, QListWidget, QMainWindow, QMessageBox,
    QMenu, QProgressBar, QPushButton, QRadioButton, QSpinBox, QSystemTrayIcon,
    QTabWidget, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from .core import VirusWall
from .network import list_connections, list_interfaces
from .report import evaluate, export_scan_results
from .signatures import sha256_file


# ---------------------------------------------------------------------------
# Темы оформления
# ---------------------------------------------------------------------------

_LIGHT_COLORS = {
    "bg": "#eef2f8", "card": "#ffffff", "card_border": "#d7e0ec",
    "text": "#1f2937", "text_muted": "#64748b", "heading": "#0f2a52",
    "accent": "#2563eb", "accent_hover": "#1d4ed8", "accent_pressed": "#1e40af",
    "accent_text": "#ffffff", "input_bg": "#ffffff", "input_border": "#c3cfe0",
    "input_text": "#1f2937", "tab_text": "#5b6b83", "tab_hover": "#e1e9f5",
    "header_bg": "#eef3fa", "header_text": "#47566e", "row_alt": "#f7fafd",
    "row_selected_bg": "#2563eb", "row_selected_text": "#ffffff",
    "banner_bg": "#e8f1fe", "banner_border": "#bcd3f5", "banner_text": "#1e3a8a",
    "muted_btn_bg": "#cfd8e6", "muted_btn_text": "#7b8899",
    "danger": "#dc2626", "danger_hover": "#b91c1c",
    "tooltip_bg": "#ffffff", "tooltip_text": "#1f2937",
}

_DARK_COLORS = {
    "bg": "#0d131d", "card": "#161d2a", "card_border": "#2a3444",
    "text": "#dbe4f0", "text_muted": "#8b9ab1", "heading": "#eaf1fb",
    "accent": "#3b82f6", "accent_hover": "#2563eb", "accent_pressed": "#1d4ed8",
    "accent_text": "#ffffff", "input_bg": "#1b2331", "input_border": "#313d50",
    "input_text": "#dbe4f0", "tab_text": "#93a3ba", "tab_hover": "#223047",
    "header_bg": "#1d2635", "header_text": "#a9b8cf", "row_alt": "#141b27",
    "row_selected_bg": "#3b82f6", "row_selected_text": "#ffffff",
    "banner_bg": "#16263d", "banner_border": "#2c4a73", "banner_text": "#bcd7ff",
    "muted_btn_bg": "#242e3d", "muted_btn_text": "#7e8ca3",
    "danger": "#ef4444", "danger_hover": "#dc2626",
    "tooltip_bg": "#202939", "tooltip_text": "#dbe4f0",
}

_STYLE_TEMPLATE = """
* { font-size: 13px; font-family: 'Segoe UI', 'Ubuntu', 'Noto Sans', sans-serif; }
QWidget { background: @bg; color: @text; }
QMainWindow, QDialog { background: @bg; }
QLabel { background: transparent; }
QLabel#heading { font-size: 22px; font-weight: 700; color: @heading; }
QLabel#subheading { font-size: 15px; font-weight: 600; color: @heading; }
QLabel#muted { color: @text_muted; }
QLabel#banner { background: @banner_bg; border: 1px solid @banner_border;
    border-radius: 8px; padding: 8px 12px; color: @banner_text; }
QTabWidget::pane { border: 1px solid @card_border; border-radius: 10px;
    background: @card; top: -1px; }
QTabBar { background: transparent; }
QTabBar::tab { background: transparent; color: @tab_text; padding: 10px 18px;
    margin: 4px 2px 0 2px; border-radius: 8px; }
QTabBar::tab:hover { background: @tab_hover; }
QTabBar::tab:selected { background: @accent; color: @accent_text; font-weight: 600; }
QPushButton { background: @accent; color: @accent_text; border: none;
    border-radius: 8px; padding: 8px 16px; font-weight: 600; }
QPushButton:hover { background: @accent_hover; }
QPushButton:pressed { background: @accent_pressed; }
QPushButton:disabled { background: @muted_btn_bg; color: @muted_btn_text; font-weight: 400; }
QPushButton#ghost { background: @card; color: @accent; border: 1px solid @card_border; }
QPushButton#ghost:hover { background: @tab_hover; }
QPushButton#ghost:disabled { background: @card; color: @muted_btn_text; }
QPushButton#danger { background: @danger; color: #ffffff; }
QPushButton#danger:hover { background: @danger_hover; }
QLineEdit, QComboBox, QSpinBox { background: @input_bg; color: @input_text;
    border: 1px solid @input_border; border-radius: 8px; padding: 6px 10px; }
QLineEdit:focus, QComboBox:focus, QSpinBox:focus { border: 1px solid @accent; }
QComboBox::drop-down { border: none; width: 24px; }
QComboBox QAbstractItemView { background: @card; color: @text;
    border: 1px solid @card_border; selection-background-color: @row_selected_bg;
    selection-color: @row_selected_text; }
QGroupBox { background: @card; border: 1px solid @card_border; border-radius: 10px;
    margin-top: 14px; padding: 12px; font-weight: 600; }
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; color: @heading; }
QTableWidget, QListWidget { background: @card; alternate-background-color: @row_alt;
    border: 1px solid @card_border; border-radius: 10px; gridline-color: transparent; }
QTableWidget::item { padding: 5px 8px; border: none; }
QTableWidget::item:selected, QListWidget::item:selected {
    background: @row_selected_bg; color: @row_selected_text; }
QHeaderView::section { background: @header_bg; color: @header_text; border: none;
    padding: 7px 8px; font-weight: 600; }
QTableCornerButton::section { background: @header_bg; border: none; }
QProgressBar { background: @input_bg; border: 1px solid @input_border;
    border-radius: 8px; height: 14px; text-align: center; color: @text; }
QProgressBar::chunk { background: @accent; border-radius: 8px; }
QCheckBox, QRadioButton { spacing: 8px; background: transparent; }
QStatusBar { background: @card; color: @text_muted; border-top: 1px solid @card_border; }
QToolTip { background: @tooltip_bg; color: @tooltip_text; border: 1px solid @card_border;
    padding: 6px; border-radius: 6px; }
QMenu { background: @card; color: @text; border: 1px solid @card_border;
    border-radius: 8px; padding: 4px; }
QMenu::item { padding: 7px 22px; border-radius: 6px; }
QMenu::item:selected { background: @row_selected_bg; color: @row_selected_text; }
QMenu::item:disabled { color: @text_muted; }
QMenu::separator { height: 1px; background: @card_border; margin: 4px 8px; }
QScrollBar:vertical { background: transparent; width: 10px; margin: 2px; }
QScrollBar::handle:vertical { background: @card_border; border-radius: 5px; min-height: 30px; }
QScrollBar::handle:vertical:hover { background: @text_muted; }
QScrollBar:horizontal { background: transparent; height: 10px; margin: 2px; }
QScrollBar::handle:horizontal { background: @card_border; border-radius: 5px; min-width: 30px; }
QScrollBar::handle:horizontal:hover { background: @text_muted; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; width: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }
"""


def build_style(colors: dict) -> str:
    """Собрать QSS из шаблона, подставив цвета выбранной темы."""
    style = _STYLE_TEMPLATE
    # Сначала длинные ключи, иначе "@text" попадёт внутрь "@text_muted" и т.п.
    for key in sorted(colors, key=len, reverse=True):
        style = style.replace("@" + key, colors[key])
    return style


STYLE = build_style(_LIGHT_COLORS)

_UI_STATE = {"theme": "light"}

# Цветные бейджи риска и результатов (фон, текст) для светлой и тёмной темы.
_BADGE_COLORS = {
    "light": {
        "low": ("#dcfce7", "#166534"), "medium": ("#fef3c7", "#92400e"),
        "high": ("#fee2e2", "#991b1b"), "clean": ("#dcfce7", "#166534"),
        "threat": ("#fee2e2", "#991b1b"), "error": ("#e2e8f0", "#475569"),
    },
    "dark": {
        "low": ("#0e2a1c", "#4ade80"), "medium": ("#332606", "#fbbf24"),
        "high": ("#3a1214", "#f87171"), "clean": ("#0e2a1c", "#4ade80"),
        "threat": ("#3a1214", "#f87171"), "error": ("#232c3b", "#94a3b8"),
    },
}

_TABLE_HINT = "Правый клик по строке — меню действий"


def make_table(headers: list[str]) -> QTableWidget:
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    table.setAlternatingRowColors(True)
    table.setShowGrid(False)
    table.horizontalHeader().setStretchLastSection(True)
    table.verticalHeader().setVisible(False)
    table.verticalHeader().setDefaultSectionSize(30)
    table.setToolTip(_TABLE_HINT)
    return table


def _colorize_badges(table: QTableWidget) -> None:
    """Раскрасить ячейки «Риск» и «Результат» по уровню, с учётом темы."""
    palette = _BADGE_COLORS[_UI_STATE["theme"]]
    for row in range(table.rowCount()):
        for col in range(table.columnCount()):
            header_item = table.horizontalHeaderItem(col)
            item = table.item(row, col)
            if header_item is None or item is None:
                continue
            text = item.text().strip().lower()
            if header_item.text() == "Риск" and text in ("low", "medium", "high"):
                background, foreground = palette[text]
            elif header_item.text() == "Результат" and text in ("clean", "threat", "error"):
                background, foreground = palette[text]
            else:
                continue
            item.setBackground(QColor(background))
            item.setForeground(QColor(foreground))


def fill_table(table: QTableWidget, rows) -> None:
    rows = list(rows)
    table.setRowCount(len(rows))
    for row_no, row in enumerate(rows):
        for col_no, value in enumerate(row):
            item = QTableWidgetItem("" if value is None else str(value))
            item.setToolTip(item.text())
            table.setItem(row_no, col_no, item)
    table.resizeColumnsToContents()
    _colorize_badges(table)


def make_banner(text: str) -> QLabel:
    """Информационная плашка с краткой инструкцией для вкладки."""
    label = QLabel("ℹ " + text)
    label.setObjectName("banner")
    label.setWordWrap(True)
    return label


def muted_label(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("muted")
    return label


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
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.setCentralWidget(self.tabs)
        self._build_dashboard()
        self._build_scanner()
        self._build_heuristic()
        self._build_processes()
        self._build_network()
        self._build_journal()
        self._build_quarantine()
        self._build_settings()
        self._set_theme(self._load_theme(), initial=True)
        self._refresh_dashboard()
        self._refresh_journal()
        self._refresh_quarantine()
        self._refresh_signatures()
        self._refresh_processes()
        self._refresh_network()
        self._background_thread = threading.Thread(target=self.app.run_background,
                                                   args=(self._background_stop,), daemon=True)
        self._background_thread.start()
        self._notify_queue: list[dict] = []
        self.app.journal.subscribe(self._queue_notification)
        self._build_tray()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._periodic_refresh)
        self.timer.start(5000)
        self.statusBar().showMessage("Готово. Сканирование и мониторинг работают локально. "
                                     "Наведите курсор на кнопку — подсказка объяснит действие.")

    # ------------------------------------------------------------------
    # Тема оформления
    # ------------------------------------------------------------------

    def _ui_settings_path(self) -> Path:
        return Path(self.app.data_dir) / "ui.json"

    def _load_theme(self) -> str:
        try:
            data = json.loads(self._ui_settings_path().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return "light"
        theme = data.get("theme")
        return theme if theme in ("light", "dark") else "light"

    def _save_theme(self, theme: str) -> None:
        path = self._ui_settings_path()
        try:
            path.write_text(json.dumps({"theme": theme}), encoding="utf-8")
        except OSError as exc:
            self._notify(f"Не удалось сохранить выбор темы: {exc}", warning=True)

    def _set_theme(self, name: str, initial: bool = False) -> None:
        """Применить тему сразу и запомнить выбор в ui.json каталога данных."""
        colors = _DARK_COLORS if name == "dark" else _LIGHT_COLORS
        _UI_STATE["theme"] = name
        self.setStyleSheet(build_style(colors))
        if hasattr(self, "light_radio") and hasattr(self, "dark_radio"):
            for radio, theme_name in ((self.light_radio, "light"), (self.dark_radio, "dark")):
                radio.blockSignals(True)
                radio.setChecked(theme_name == name)
                radio.blockSignals(False)
        if hasattr(self, "theme_button"):
            self.theme_button.setText("☀ Светлая тема" if name == "dark" else "🌙 Тёмная тема")
        if not initial:
            self._refill_tables()
            self._save_theme(name)
            self.statusBar().showMessage(
                f"Тема переключена: {'тёмная' if name == 'dark' else 'светлая'}. Выбор сохранён.", 6000)

    def _toggle_theme(self) -> None:
        self._set_theme("dark" if _UI_STATE["theme"] == "light" else "light")

    def _refill_tables(self) -> None:
        """Перерисовать таблицы, чтобы цветные бейджи соответствовали теме."""
        if self.results:
            self._fill_scan_results(self.results)
        else:
            fill_table(self.scan_table, [])
            fill_table(self.heuristic_table, [])
        self._refresh_dashboard()
        self._refresh_journal()
        self._refresh_quarantine()
        self._refresh_signatures()
        if self.tabs.currentIndex() == 3:
            self._refresh_processes()
        elif self.tabs.currentIndex() == 4:
            self._refresh_network()

    # ------------------------------------------------------------------
    # Служебные методы
    # ------------------------------------------------------------------

    def _queue_notification(self, record: dict) -> None:
        """Подписчик журнала: готовит высокоуровневые события к системному уведомлению."""
        if record.get("severity") not in ("high", "critical") or record.get("event_type") == "file_scan":
            return
        self._notify_queue.append(record)

    def _build_tray(self) -> None:
        if not QSystemTrayIcon.isSystemTrayAvailable():
            self.tray = None
            return
        try:
            from PySide6.QtGui import QIcon
            style = self.style()
            self.tray = QSystemTrayIcon(style.standardIcon(style.StandardPixmap.SP_ComputerIcon), self)
            self.tray.setToolTip("VirusWall — антивирусный анализатор")
            self.tray.show()
        except (OSError, RuntimeError):
            self.tray = None

    def _drain_notifications(self) -> None:
        """Показать системное уведомление (Ф-22) для последних находок."""
        while self._notify_queue:
            record = self._notify_queue.pop(0)
            title = {"realtime_detection": "Защита в реальном времени",
                     "realtime_event": None,
                     "process": "Поведенческий анализ", "network": "Сетевой анализ",
                     "quarantine_limit": "Карантин", "tamper_detected": "Самозащита"}.get(
                record.get("event_type"), "VirusWall")
            if title is None:
                continue
            text = f"{record.get('threat_name') or 'Событие'}: {record.get('target', '')}"
            if getattr(self, "tray", None) is not None:
                self.tray.showMessage(title, text[:200])
            else:
                self.statusBar().showMessage(f"{title}: {text[:200]}", 10000)
            break

    def _new_tab(self, title: str, help_text: str = "") -> QVBoxLayout:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(18, 14, 18, 16)
        layout.setSpacing(10)
        if help_text:
            layout.addWidget(make_banner(help_text))
        self.tabs.addTab(widget, title)
        return layout

    # ------------------------------------------------------------------
    # Построение вкладок
    # ------------------------------------------------------------------

    def _build_dashboard(self) -> None:
        layout = self._new_tab(
            "Главная",
            "Краткая инструкция: здесь видно общее состояние защиты и последние обнаружения. "
            "Нажмите «Быстрое сканирование», чтобы проверить папку «Загрузки». "
            "Правый клик по таблице обнаружений — скопировать объект или перейти в журнал.")
        heading = QLabel("Состояние VirusWall")
        heading.setObjectName("heading")
        layout.addWidget(heading)
        layout.addWidget(muted_label(
            "Учебный анализатор: сканирование по запросу и пассивный мониторинг. "
            "Файлы не удаляются автоматически."))
        self.status_label = QLabel()
        self.status_label.setObjectName("subheading")
        layout.addWidget(self.status_label)
        self.errors_label = QLabel()
        self.errors_label.setWordWrap(True)
        self.errors_label.setObjectName("muted")
        layout.addWidget(self.errors_label)
        row = QHBoxLayout()
        self.quick_button = QPushButton("Быстрое сканирование")
        self.quick_button.setToolTip("Запускает сканирование папки «Загрузки» (или текущего каталога). "
                                     "Пока идёт проверка, кнопки сканирования заблокированы.")
        self.quick_button.setStatusTip("Сканировать папку «Загрузки»")
        self.quick_button.clicked.connect(self._quick_scan)
        row.addWidget(self.quick_button)
        self.theme_button = QPushButton("🌙 Тёмная тема")
        self.theme_button.setObjectName("ghost")
        self.theme_button.setToolTip("Переключает оформление окна: светлое ↔ тёмное. "
                                     "Выбор автоматически сохраняется и восстановится при следующем запуске.")
        self.theme_button.setStatusTip("Переключить тему оформления")
        self.theme_button.clicked.connect(self._toggle_theme)
        row.addWidget(self.theme_button)
        row.addStretch()
        layout.addLayout(row)
        subheading = QLabel("Последние обнаружения")
        subheading.setObjectName("subheading")
        layout.addWidget(subheading)
        self.threat_table = make_table(["Время", "Источник", "Объект", "Угроза", "Риск"])
        self.threat_table.setToolTip("Живые находки из журнала (события среднего и высокого риска). "
                                     + _TABLE_HINT)
        self._attach_context_menu(self.threat_table, self._threat_context_menu)
        layout.addWidget(self.threat_table)

    def _build_scanner(self) -> None:
        layout = self._new_tab(
            "Сканирование",
            "Краткая инструкция: 1) выберите файл или каталог кнопками «Файл…»/«Каталог…»; "
            "2) нажмите «Сканировать» — результаты появятся в таблице; "
            "3) кнопка «Экспорт отчёта…» сохранит отчёт в JSON или CSV. "
            "Правый клик по результату — повторное сканирование, копирование пути/хэша, карантин.")
        row = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("Выберите файл или каталог")
        self.path_edit.setToolTip("Поле пути для проверки: заполните кнопками «Файл…»/«Каталог…» или введите вручную.")
        self.path_edit.setStatusTip("Путь к проверяемому файлу или каталогу")
        row.addWidget(self.path_edit)
        file_button = QPushButton("Файл…")
        file_button.setObjectName("ghost")
        file_button.setToolTip("Откроет диалог выбора файла и подставит его путь в поле слева.")
        file_button.setStatusTip("Выбрать файл для сканирования")
        file_button.clicked.connect(self._choose_file)
        row.addWidget(file_button)
        dir_button = QPushButton("Каталог…")
        dir_button.setObjectName("ghost")
        dir_button.setToolTip("Откроет диалог выбора папки и подставит её путь в поле слева. "
                              "Будет просканировано всё её содержимое (кроме исключений).")
        dir_button.setStatusTip("Выбрать каталог для сканирования")
        dir_button.clicked.connect(self._choose_directory)
        row.addWidget(dir_button)
        self.scan_button = QPushButton("Сканировать")
        self.scan_button.setToolTip("Запустит проверку выбранного пути в фоновом потоке. "
                                    "Результат появится в таблице ниже; кнопки блокируются до завершения.")
        self.scan_button.setStatusTip("Запустить сканирование выбранного пути")
        self.scan_button.clicked.connect(self._scan_selected)
        row.addWidget(self.scan_button)
        layout.addLayout(row)
        self.scan_progress = QProgressBar()
        self.scan_progress.setToolTip("Индикатор работы: показывается, пока идёт сканирование.")
        self.scan_progress.hide()
        layout.addWidget(self.scan_progress)
        self.scan_summary = QLabel("Выберите объект для проверки.")
        self.scan_summary.setObjectName("subheading")
        layout.addWidget(self.scan_summary)
        self.scan_table = make_table(["Путь", "SHA-256", "Результат", "Угроза", "Время"])
        self.scan_table.setToolTip("Результаты последнего сканирования: «clean» — чисто, "
                                   "«threat» — найдена угроза, «error» — не удалось прочитать. "
                                   + _TABLE_HINT)
        self._attach_context_menu(self.scan_table, self._scan_context_menu)
        layout.addWidget(self.scan_table)
        self.export_button = QPushButton("Экспорт отчёта JSON/CSV…")
        self.export_button.setEnabled(False)
        self.export_button.setToolTip("Откроет диалог сохранения отчёта по последнему сканированию "
                                      "(JSON или CSV). Кнопка активна только после сканирования.")
        self.export_button.setStatusTip("Сохранить отчёт о сканировании")
        self.export_button.clicked.connect(self._export_report)
        layout.addWidget(self.export_button, alignment=Qt.AlignmentFlag.AlignLeft)

    def _build_heuristic(self) -> None:
        layout = self._new_tab(
            "Эвристика",
            "Краткая инструкция: таблица показывает подозрительные признаки, которые эвристика нашла "
            "во время последнего сканирования (формат, расширение, опасные строки, упаковка). "
            "Чтобы обновить данные — выполните новое сканирование на вкладке «Сканирование». "
            "Порог чувствительности настраивается на вкладке «Настройки».")
        layout.addWidget(muted_label(
            "Эвристика учитывает формат, расширение, подозрительные строки и признаки упаковки. "
            "Заполнена после последнего сканирования."))
        self.heuristic_label = QLabel()
        self.heuristic_label.setObjectName("muted")
        layout.addWidget(self.heuristic_label)
        self.heuristic_table = make_table(["Файл", "Правило", "Описание", "Риск"])
        self.heuristic_table.setToolTip("Срабатывания эвристических правил. "
                                        "Колонка «Риск» показывает серьёзность каждого признака.")
        layout.addWidget(self.heuristic_table)

    def _build_processes(self) -> None:
        layout = self._new_tab(
            "Процессы",
            "Краткая инструкция: нажмите «Обновить», чтобы получить свежий снимок процессов и оценки "
            "поведенческого анализа (подозрительные родитель→потомок цепочки и признаки). "
            "Правый клик по строке — скопировать PID, имя или путь запуска.")
        row = QHBoxLayout()
        self.process_label = QLabel("Список процессов")
        self.process_label.setObjectName("subheading")
        row.addWidget(self.process_label)
        row.addStretch()
        button = QPushButton("Обновить")
        button.setToolTip("Получит свежий снимок процессов через psutil и заново выполнит "
                          "поведенческий анализ; подозрительные признаки появятся в последней колонке.")
        button.setStatusTip("Обновить список процессов")
        button.clicked.connect(self._refresh_processes)
        row.addWidget(button)
        layout.addLayout(row)
        self.process_table = make_table(["PID", "Имя", "Исполняемый файл", "Подозрительные признаки"])
        self.process_table.setToolTip("Снимок запущенных процессов с оценками поведения. "
                                      + _TABLE_HINT)
        self._attach_context_menu(self.process_table, self._process_context_menu)
        layout.addWidget(self.process_table)

    def _build_network(self) -> None:
        layout = self._new_tab(
            "Сеть",
            "Краткая инструкция: верхняя таблица — текущие сетевые соединения (обновляется кнопкой "
            "«Обновить»). Для захвата пакетов выберите интерфейс и нажмите «Захватить 20 пакетов» — "
            "результат появится в нижней таблице. Правый клик — копирование адресов.")
        row = QHBoxLayout()
        self.network_label = QLabel("Пассивное наблюдение")
        self.network_label.setObjectName("subheading")
        row.addWidget(self.network_label)
        row.addStretch()
        self.interface_combo = QComboBox()
        self.interface_combo.setToolTip("Сетевой интерфейс, на котором будет выполняться захват пакетов. "
                                        "Список заполняется автоматически.")
        self.interface_combo.setStatusTip("Выбрать сетевой интерфейс")
        row.addWidget(self.interface_combo)
        refresh = QPushButton("Обновить")
        refresh.setObjectName("ghost")
        refresh.setToolTip("Обновит список интерфейсов и текущих сетевых соединений.")
        refresh.setStatusTip("Обновить сетевые данные")
        refresh.clicked.connect(self._refresh_network)
        row.addWidget(refresh)
        self.capture_button = QPushButton("Захватить 20 пакетов")
        self.capture_button.setToolTip("Перехватит 20 пакетов через выбранный интерфейс (Scapy; "
                                       "на Linux может потребоваться права root). "
                                       "Кнопка блокируется на время захвата.")
        self.capture_button.setStatusTip("Захватить пакеты выбранного интерфейса")
        self.capture_button.clicked.connect(self._start_capture)
        row.addWidget(self.capture_button)
        layout.addLayout(row)
        self.connection_table = make_table(["Протокол", "Локальный адрес", "Удалённый адрес", "Состояние", "PID", "Направление"])
        self.connection_table.setToolTip("Активные TCP/UDP соединения системы. "
                                         "Направление TCP определяется приблизительно. " + _TABLE_HINT)
        self._attach_context_menu(self.connection_table, self._network_context_menu)
        layout.addWidget(self.connection_table)
        subheading = QLabel("Последний захват пакетов")
        subheading.setObjectName("subheading")
        layout.addWidget(subheading)
        self.packet_table = make_table(["Время", "Источник", "Назначение", "Протокол", "DNS", "Правило"])
        self.packet_table.setToolTip("Метаданные пакетов последнего захвата и сработавшие правила. "
                                     + _TABLE_HINT)
        self._attach_context_menu(self.packet_table, self._packet_context_menu)
        layout.addWidget(self.packet_table)

    def _build_journal(self) -> None:
        layout = self._new_tab(
            "Журнал",
            "Краткая инструкция: журнал хранит все события. Введите часть источника или выберите уровень — "
            "и нажмите «Фильтровать». Правый клик по записи — скопировать объект или сбросить фильтры.")
        row = QHBoxLayout()
        self.source_filter = QLineEdit()
        self.source_filter.setPlaceholderText("Источник (необязательно)")
        self.source_filter.setToolTip("Фильтр по источнику события (например «scanner» или «network»). "
                                      "Применяется кнопкой «Фильтровать»; пустое поле — без фильтра.")
        self.source_filter.setStatusTip("Фильтр журнала по источнику")
        row.addWidget(self.source_filter)
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["Все уровни", "low", "medium", "high"])
        self.severity_filter.setToolTip("Выбор минимального уровня серьёзности для фильтра журнала.")
        self.severity_filter.setStatusTip("Фильтр журнала по уровню риска")
        row.addWidget(self.severity_filter)
        button = QPushButton("Фильтровать")
        button.setToolTip("Применит введённые фильтры и перечитает журнал "
                          "(показываются последние 200 записей).")
        button.setStatusTip("Применить фильтры журнала")
        button.clicked.connect(self._refresh_journal)
        row.addWidget(button)
        reset_button = QPushButton("Сбросить фильтры")
        reset_button.setObjectName("ghost")
        reset_button.setToolTip("Очистит фильтры и покажет весь журнал.")
        reset_button.setStatusTip("Сбросить фильтры журнала")
        reset_button.clicked.connect(self._reset_journal_filters)
        row.addWidget(reset_button)
        layout.addLayout(row)
        self.event_table = make_table(["Время", "Тип", "Источник", "Объект", "Угроза", "Риск", "Действие", "Результат"])
        self.event_table.setToolTip("Полный журнал событий с фильтрами. " + _TABLE_HINT)
        self._attach_context_menu(self.event_table, self._journal_context_menu)
        layout.addWidget(self.event_table)

    def _build_quarantine(self) -> None:
        layout = self._new_tab(
            "Карантин",
            "Краткая инструкция: чтобы изолировать файл, укажите название угрозы (при желании включите "
            "удаление оригинала) и нажмите «Поместить файл…» — потребуется подтверждение. "
            "Для возврата выделите запись и нажмите «Восстановить выбранный». "
            "Правый клик по записи — восстановление и копирование пути.")
        layout.addWidget(muted_label(
            "Файл помещается только после подтверждения. По умолчанию оригинал остаётся на месте, "
            "в карантин сохраняется шифрованная копия (AES-256-GCM)."))
        row = QHBoxLayout()
        self.threat_name_edit = QLineEdit("Manual.Suspicious")
        self.threat_name_edit.setPlaceholderText("Название угрозы")
        self.threat_name_edit.setToolTip("Название угрозы, которое будет записано в карточку карантина. "
                                         "Можно оставить предложенное по умолчанию.")
        self.threat_name_edit.setStatusTip("Название угрозы для карантина")
        row.addWidget(self.threat_name_edit)
        self.remove_original_check = QCheckBox("Изолировать: убрать исходный файл после сохранения копии")
        self.remove_original_check.setToolTip("Если включить: оригинал будет безопасно удалён после "
                                              "сохранения шифрованной копии; если выключить — файл останется на месте.")
        self.remove_original_check.setStatusTip("Удалить оригинал после изоляции")
        row.addWidget(self.remove_original_check)
        put_button = QPushButton("Поместить файл…")
        put_button.setToolTip("Откроет диалог выбора файла и после подтверждения сохранит его "
                              "шифрованную копию в карантине.")
        put_button.setStatusTip("Поместить файл в карантин")
        put_button.clicked.connect(self._quarantine_file)
        row.addWidget(put_button)
        layout.addLayout(row)
        self.quarantine_table = make_table(["ID", "Исходный путь", "Угроза", "Дата", "Оригинал убран"])
        self.quarantine_table.setToolTip("Объекты в карантине. " + _TABLE_HINT)
        self._attach_context_menu(self.quarantine_table, self._quarantine_context_menu)
        layout.addWidget(self.quarantine_table)
        row = QHBoxLayout()
        restore_button = QPushButton("Восстановить выбранный")
        restore_button.setToolTip("Расшифрует выделенный объект и вернёт его в исходный путь; "
                                  "если путь занят — предложит выбрать новое место.")
        restore_button.setStatusTip("Восстановить объект из карантина")
        restore_button.clicked.connect(self._restore_file)
        row.addWidget(restore_button)
        refresh_button = QPushButton("Обновить список")
        refresh_button.setObjectName("ghost")
        refresh_button.setToolTip("Перечитает список объектов карантина.")
        refresh_button.setStatusTip("Обновить список карантина")
        refresh_button.clicked.connect(self._refresh_quarantine)
        row.addWidget(refresh_button)
        row.addStretch()
        layout.addLayout(row)

    def _build_settings(self) -> None:
        layout = self._new_tab(
            "Настройки",
            "Краткая инструкция: изменения модулей и чувствительности применяются кнопкой "
            "«Сохранить настройки». Тема оформления меняется сразу и запоминается сама. "
            "Исключения, наблюдение за каталогом и тестовые сигнатуры настраиваются кнопками ниже; "
            "правый клик по спискам — быстрые действия.")
        theme_box = QGroupBox("Тема интерфейса")
        theme_layout = QHBoxLayout(theme_box)
        self.light_radio = QRadioButton("Светлая")
        self.light_radio.setToolTip("Применит светлую тему оформления. "
                                    "Действует сразу; выбор сохраняется в ui.json.")
        self.light_radio.setStatusTip("Светлая тема оформления")
        self.light_radio.toggled.connect(lambda checked: checked and self._set_theme("light"))
        theme_layout.addWidget(self.light_radio)
        self.dark_radio = QRadioButton("Тёмная")
        self.dark_radio.setToolTip("Применит тёмную тему оформления (в стиле современных антивирусов). "
                                   "Действует сразу; выбор сохраняется в ui.json.")
        self.dark_radio.setStatusTip("Тёмная тема оформления")
        self.dark_radio.toggled.connect(lambda checked: checked and self._set_theme("dark"))
        theme_layout.addWidget(self.dark_radio)
        theme_layout.addStretch()
        layout.addWidget(theme_box)
        module_box = QGroupBox("Модули защиты")
        module_layout = QVBoxLayout(module_box)
        self.module_checks = {}
        for name, enabled in self.app.config.modules.items():
            check = QCheckBox(name)
            check.setChecked(enabled)
            check.setToolTip(f"Включает или отключает модуль «{name}». "
                             "Изменение вступит в силу после нажатия «Сохранить настройки».")
            module_layout.addWidget(check)
            self.module_checks[name] = check
        layout.addWidget(module_box)
        form = QFormLayout()
        self.sensitivity_spin = QSpinBox()
        self.sensitivity_spin.setRange(0, 100)
        self.sensitivity_spin.setValue(self.app.config.heuristic_sensitivity)
        self.sensitivity_spin.setToolTip("Порог чувствительности эвристики (0–100): выше — больше находок, "
                                         "но и больше ложных срабатываний. "
                                         "Применяется после «Сохранить настройки».")
        self.sensitivity_spin.setStatusTip("Чувствительность эвристики")
        form.addRow("Чувствительность эвристики", self.sensitivity_spin)
        layout.addLayout(form)
        save_button = QPushButton("Сохранить настройки")
        save_button.setToolTip("Запишет состояние модулей и чувствительность в config.json "
                               "(предварительно создаст резервную копию).")
        save_button.setStatusTip("Сохранить настройки в config.json")
        save_button.clicked.connect(self._save_settings)
        layout.addWidget(save_button, alignment=Qt.AlignmentFlag.AlignLeft)
        subheading = QLabel("Исключения сканирования")
        subheading.setObjectName("subheading")
        layout.addWidget(subheading)
        self.exclusion_list = QListWidget()
        self.exclusion_list.addItems(self.app.config.exclusions)
        self.exclusion_list.setToolTip("Пути и маски, которые сканер пропускает. "
                                       "Правый клик — добавить или убрать исключение.")
        self._attach_context_menu(self.exclusion_list, self._exclusion_context_menu)
        layout.addWidget(self.exclusion_list)
        row = QHBoxLayout()
        add_button = QPushButton("Добавить путь…")
        add_button.setToolTip("Откроет выбор папки; она будет добавлена в исключения "
                              "и пропускаться при сканировании.")
        add_button.setStatusTip("Добавить каталог в исключения")
        add_button.clicked.connect(self._add_exclusion)
        row.addWidget(add_button)
        remove_button = QPushButton("Убрать исключение")
        remove_button.setObjectName("danger")
        remove_button.setToolTip("Удалит выделенную строку из списка исключений "
                                 "(сразу сохраняет config.json).")
        remove_button.setStatusTip("Убрать выделенное исключение")
        remove_button.clicked.connect(self._remove_exclusion)
        row.addWidget(remove_button)
        row.addStretch()
        layout.addLayout(row)
        subheading = QLabel("Контроль файловой системы (защита в реальном времени)")
        subheading.setObjectName("subheading")
        layout.addWidget(subheading)
        self.watch_label = QLabel("Остановлен")
        self.watch_label.setObjectName("muted")
        layout.addWidget(self.watch_label)
        row = QHBoxLayout()
        start_watch = QPushButton("Следить за каталогом…")
        start_watch.setToolTip("Откроет выбор папки и включит защиту в реальном времени: "
                               "изменения файлов будут проверяться сразу (watchdog/inotify).")
        start_watch.setStatusTip("Включить наблюдение за каталогом")
        start_watch.clicked.connect(self._start_watch)
        row.addWidget(start_watch)
        stop_watch = QPushButton("Остановить")
        stop_watch.setObjectName("ghost")
        stop_watch.setToolTip("Остановит наблюдение за каталогом и вернёт индикатор в состояние «Остановлен».")
        stop_watch.setStatusTip("Остановить наблюдение")
        stop_watch.clicked.connect(self._stop_watch)
        row.addWidget(stop_watch)
        row.addStretch()
        layout.addLayout(row)
        subheading = QLabel("Локальная база сигнатур")
        subheading.setObjectName("subheading")
        layout.addWidget(subheading)
        self.signature_table = make_table(["SHA-256", "Имя", "Категория"])
        self.signature_table.setToolTip("Локальная база сигнатур (хэши известных угроз). "
                                        "Правый клик — скопировать хэш или удалить сигнатуру.")
        self._attach_context_menu(self.signature_table, self._signature_context_menu)
        layout.addWidget(self.signature_table)
        row = QHBoxLayout()
        add_signature = QPushButton("Добавить сигнатуру файла…")
        add_signature.setToolTip("Выберет файл, спросит название угрозы и добавит его SHA-256 "
                                 "в базу как тестовую сигнатуру.")
        add_signature.setStatusTip("Добавить сигнатуру в базу")
        add_signature.clicked.connect(self._add_signature)
        row.addWidget(add_signature)
        remove_signature = QPushButton("Удалить выбранную")
        remove_signature.setObjectName("danger")
        remove_signature.setToolTip("Удалит выделенную сигнатуру из базы после подтверждения.")
        remove_signature.setStatusTip("Удалить выбранную сигнатуру")
        remove_signature.clicked.connect(self._remove_signature)
        row.addWidget(remove_signature)
        row.addStretch()
        layout.addLayout(row)

    # ------------------------------------------------------------------
    # Контекстные меню (правая кнопка мыши)
    # ------------------------------------------------------------------

    def _attach_context_menu(self, widget, handler) -> None:
        widget.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        widget.customContextMenuRequested.connect(lambda pos: handler(pos))

    def _copy_text(self, text: str, what: str = "") -> None:
        QGuiApplication.clipboard().setText(text)
        suffix = f" ({what})" if what else ""
        self.statusBar().showMessage(f"Скопировано в буфер обмена{suffix}: {text[:100]}", 6000)

    def _copy_cell(self, table: QTableWidget, row: int, col: int, what: str) -> None:
        item = table.item(row, col)
        if item is not None:
            self._copy_text(item.text(), what)

    def _menu(self) -> QMenu:
        return QMenu(self)

    def _table_menu(self, table: QTableWidget, pos) -> tuple[QMenu, int | None]:
        menu = QMenu(self)
        row = table.rowAt(pos.y())
        if row < 0:
            self.statusBar().showMessage(
                "Правый клик работает по строке таблицы: наведите курсор на строку и повторите.", 6000)
            return menu, None
        return menu, row

    def _exec_menu(self, widget, pos, menu: QMenu) -> None:
        """Показать меню по координатам виджета (единая точка для тестов)."""
        menu.exec(widget.mapToGlobal(pos.toPoint() if hasattr(pos, "toPoint") else pos))

    def _run_menu(self, table: QTableWidget, pos, menu: QMenu) -> None:
        self._exec_menu(table.viewport(), pos, menu)

    def _scan_context_menu(self, pos) -> None:
        table = self.scan_table
        menu, row = self._table_menu(table, pos)
        if row is None:
            return
        path = table.item(row, 0).text()
        menu.addAction("Повторно просканировать этот путь",
                       lambda: self._start_scan(Path(path)))
        menu.addAction("Копировать путь", lambda: self._copy_cell(table, row, 0, "путь"))
        menu.addAction("Копировать SHA-256", lambda: self._copy_cell(table, row, 1, "хэш"))
        menu.addSeparator()
        menu.addAction("Поместить путь в карантин…",
                       lambda: self._quarantine_path(Path(path)))
        menu.addSeparator()
        menu.addAction("Экспорт отчёта JSON/CSV…", self._export_report)
        self._run_menu(table, pos, menu)

    def _threat_context_menu(self, pos) -> None:
        table = self.threat_table
        menu, row = self._table_menu(table, pos)
        if row is None:
            return
        menu.addAction("Копировать объект", lambda: self._copy_cell(table, row, 2, "объект"))
        menu.addAction("Копировать название угрозы",
                       lambda: self._copy_cell(table, row, 3, "угроза"))
        menu.addSeparator()
        menu.addAction("Перейти в журнал событий", lambda: self.tabs.setCurrentIndex(5))
        self._run_menu(table, pos, menu)

    def _process_context_menu(self, pos) -> None:
        table = self.process_table
        menu, row = self._table_menu(table, pos)
        if row is None:
            return
        menu.addAction("Копировать PID", lambda: self._copy_cell(table, row, 0, "PID"))
        menu.addAction("Копировать имя процесса", lambda: self._copy_cell(table, row, 1, "имя"))
        menu.addAction("Копировать путь EXE", lambda: self._copy_cell(table, row, 2, "путь"))
        self._run_menu(table, pos, menu)

    def _network_context_menu(self, pos) -> None:
        table = self.connection_table
        menu, row = self._table_menu(table, pos)
        if row is None:
            menu.addAction("Обновить список соединений", self._refresh_network)
        else:
            menu.addAction("Копировать локальный адрес",
                           lambda: self._copy_cell(table, row, 1, "локальный адрес"))
            menu.addAction("Копировать удалённый адрес",
                           lambda: self._copy_cell(table, row, 2, "удалённый адрес"))
            menu.addSeparator()
            menu.addAction("Обновить список соединений", self._refresh_network)
        self._run_menu(table, pos, menu)

    def _packet_context_menu(self, pos) -> None:
        table = self.packet_table
        menu, row = self._table_menu(table, pos)
        if row is None:
            return
        menu.addAction("Копировать источник", lambda: self._copy_cell(table, row, 1, "источник"))
        menu.addAction("Копировать назначение", lambda: self._copy_cell(table, row, 2, "назначение"))
        menu.addAction("Копировать DNS-запрос", lambda: self._copy_cell(table, row, 4, "DNS"))
        self._run_menu(table, pos, menu)

    def _journal_context_menu(self, pos) -> None:
        table = self.event_table
        menu, row = self._table_menu(table, pos)
        if row is None:
            menu.addAction("Сбросить фильтры", self._reset_journal_filters)
        else:
            menu.addAction("Копировать объект", lambda: self._copy_cell(table, row, 3, "объект"))
            menu.addAction("Копировать угрозу", lambda: self._copy_cell(table, row, 4, "угрозу"))
            menu.addAction("Копировать всю запись",
                           lambda: self._copy_text(" | ".join(
                               table.item(row, c).text() for c in range(table.columnCount())
                               if table.item(row, c) is not None), "запись журнала"))
            menu.addSeparator()
            menu.addAction("Сбросить фильтры", self._reset_journal_filters)
        self._run_menu(table, pos, menu)

    def _quarantine_context_menu(self, pos) -> None:
        table = self.quarantine_table
        menu, row = self._table_menu(table, pos)
        if row is None:
            menu.addAction("Обновить список", self._refresh_quarantine)
        else:
            menu.addAction("Восстановить этот объект…", lambda: self._restore_row(row))
            menu.addAction("Копировать исходный путь",
                           lambda: self._copy_cell(table, row, 1, "путь"))
            menu.addSeparator()
            menu.addAction("Обновить список", self._refresh_quarantine)
        self._run_menu(table, pos, menu)

    def _signature_context_menu(self, pos) -> None:
        table = self.signature_table
        menu, row = self._table_menu(table, pos)
        if row is None:
            menu.addAction("Добавить сигнатуру файла…", self._add_signature)
        else:
            menu.addAction("Копировать SHA-256", lambda: self._copy_cell(table, row, 0, "хэш"))
            menu.addSeparator()
            menu.addAction("Удалить выбранную сигнатуру…", self._remove_signature)
        self._run_menu(table, pos, menu)

    def _exclusion_context_menu(self, pos) -> None:
        widget = self.exclusion_list
        item = widget.itemAt(pos.toPoint() if hasattr(pos, "toPoint") else pos)
        if item is None:
            self._notify("Щёлкните правой кнопкой мыши по строке списка исключений.")
            return
        menu = self._menu()
        menu.addAction("Копировать путь", lambda: self._copy_text(item.text(), "исключение"))
        menu.addSeparator()
        menu.addAction("Убрать это исключение", lambda: self._remove_exclusion())
        self._exec_menu(widget, pos, menu)

    # ------------------------------------------------------------------
    # Действия интерфейса
    # ------------------------------------------------------------------

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
        path, _ = QFileDialog.getOpenFileName(self, "Выберите файл для сканирования")
        if path:
            self.path_edit.setText(path)
            self.statusBar().showMessage("Файл выбран. Нажмите «Сканировать» для проверки.", 6000)

    def _choose_directory(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Выберите каталог для сканирования")
        if path:
            self.path_edit.setText(path)
            self.statusBar().showMessage("Каталог выбран. Нажмите «Сканировать» для проверки.", 6000)

    def _quick_scan(self) -> None:
        default = Path.home() / "Downloads"
        self._start_scan(default if default.is_dir() else Path.cwd())

    def _scan_selected(self) -> None:
        text = self.path_edit.text().strip()
        if not text:
            self._notify("Сначала выберите файл или каталог кнопками «Файл…»/«Каталог…».", warning=True)
            return
        self._start_scan(Path(text).expanduser())

    def _start_scan(self, path: Path) -> None:
        if self._scan_worker and self._scan_worker.isRunning():
            self._notify("Сканирование уже выполняется — дождитесь завершения.")
            return
        if not path.exists():
            self._notify(f"Путь не найден: {path}", warning=True)
            return
        self.scan_button.setEnabled(False)
        self.quick_button.setEnabled(False)
        self.scan_progress.setRange(0, 0)
        self.scan_progress.show()
        self.scan_summary.setText(f"Проверяется: {path}")
        self.statusBar().showMessage(f"Сканирование началось: {path}")
        self._scan_worker = ScanWorker(self.app, path, self)
        self._scan_worker.completed.connect(self._scan_completed)
        self._scan_worker.failed.connect(lambda error: self._notify(f"Ошибка сканирования: {error}", warning=True))
        self._scan_worker.finished.connect(self._scan_finished)
        self._scan_worker.start()

    def _scan_completed(self, results) -> None:
        self.results = results
        self._fill_scan_results(results)
        self._refresh_dashboard()
        self._refresh_journal()
        summary = evaluate(results)
        if summary["threats_detected"]:
            self._notify(f"Обнаружено подозрительных объектов: {summary['threats_detected']}", warning=True)

    def _fill_scan_results(self, results) -> None:
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

    def _scan_finished(self) -> None:
        self.scan_button.setEnabled(True)
        self.quick_button.setEnabled(True)
        self.scan_progress.hide()
        self.statusBar().showMessage("Сканирование завершено. Результаты — в таблице.", 8000)

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
            self.process_label.setText("Модуль процессов отключён (включите на вкладке «Настройки»)")
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
                self.network_label.setText("Сетевой модуль отключён (включите на вкладке «Настройки»)")
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
            self._notify("Выберите сетевой интерфейс в выпадающем списке.", warning=True)
            return
        if self._capture_worker and self._capture_worker.isRunning():
            self._notify("Захват пакетов уже выполняется — дождитесь завершения.")
            return
        self.capture_button.setEnabled(False)
        self.statusBar().showMessage(f"Захват пакетов на {interface}: собирается 20 пакетов…")
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

    def _reset_journal_filters(self) -> None:
        self.source_filter.clear()
        self.severity_filter.setCurrentIndex(0)
        self._refresh_journal()
        self._notify("Фильтры журнала сброшены")

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
        if path:
            self._quarantine_path(Path(path))

    def _quarantine_path(self, path: Path) -> None:
        """Изолировать файл по подтверждению (используется кнопкой и контекстным меню)."""
        if not path.exists():
            self._notify(f"Путь не найден: {path}", warning=True)
            return
        remove_original = self.remove_original_check.isChecked()
        action = "изолировать и убрать исходный файл" if remove_original else "сохранить шифрованную копию (оригинал останется на месте)"
        if QMessageBox.question(self, "Подтверждение",
                                f"Что будет сделано: {action}.\n\nФайл: {path}\n\nПродолжить?"
                                ) != QMessageBox.StandardButton.Yes:
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
            self._notify("Сначала выделите строку в таблице карантина.", warning=True)
            return
        self._restore_row(row)

    def _restore_row(self, row: int) -> None:
        """Восстановить объект карантина по номеру строки (кнопка или контекстное меню)."""
        table = self.quarantine_table
        item_id = table.item(row, 0).text()
        original = Path(table.item(row, 1).text())
        target = None
        if original.exists():
            target, _ = QFileDialog.getSaveFileName(self, "Исходный путь занят — выберите новый", str(original))
            if not target:
                return
        if QMessageBox.question(self, "Подтверждение",
                                f"Файл будет расшифрован и возвращён: {original}.\n\nВосстановить объект {item_id}?"
                                ) != QMessageBox.StandardButton.Yes:
            return
        try:
            restored = self.app.restore_file(item_id, confirm=True, target=target)
            self._refresh_quarantine()
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
            self._notify(f"Исключение добавлено: {path}")

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
            monitor = self.app.realtime_monitor(path)
            monitor.start()
            self._watch_stop = None
            self._watch_thread = None
            self._watch_monitor = monitor
            self._watch_path = path
            policy = self.app.config.realtime["action_on_detection"]
            self.watch_label.setText(f"Защита (реальное время): {path}\n"
                                     f"Backend: {monitor.backend}; политика: {policy}; "
                                     f"автокарантин: {'включён' if monitor.armed else 'выключен'}")
            self._notify("Защита каталога в реальном времени запущена")
        except (OSError, RuntimeError) as exc:
            self._notify(str(exc), warning=True)

    def _stop_watch(self) -> None:
        monitor = getattr(self, "_watch_monitor", None) or (self._watch_thread and None)
        if monitor is not None:
            monitor.stop()
            self._watch_monitor = None
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
            self._notify("Сначала выделите сигнатуру в таблице.", warning=True)
            return
        digest = self.signature_table.item(row, 0).text()
        if QMessageBox.question(self, "Подтверждение",
                                "Сигнатура будет удалена из локальной базы. Продолжить?"
                                ) != QMessageBox.StandardButton.Yes:
            return
        self.app.signatures.remove(digest)
        self._refresh_signatures()
        self._refresh_dashboard()
        self._notify("Сигнатура удалена")

    def _periodic_refresh(self) -> None:
        self._refresh_dashboard()
        self._refresh_journal()
        self._drain_notifications()
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
        try:
            self.app.lock.release()
        except (OSError, RuntimeError):
            pass
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
