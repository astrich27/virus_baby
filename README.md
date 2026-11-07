# VirusWall

Учебное кроссплатформенное приложение для анализа файлов, процессов и сетевой активности. Лабораторные №1–2 представлены исходными DOCX-документами; реализация лабораторных №3–6 находится в пакете `viruswall`.

Приложение выполняет сканирование по запросу, пассивное наблюдение за выбранным каталогом, процессами и сетевыми соединениями. Оно показывает подозрительные события, записывает их в локальный журнал и позволяет вручную поместить файл в шифрованный карантин. Никакие файлы не удаляются автоматически. Системный перехват операций ОС, фоновая служба, автоматическое обновление баз и гарантированная блокировка вредоносного ПО в этой версии не реализованы. Это важно при демонстрации: статус «включён» означает доступность модуля анализа, а не полную защиту в реальном времени.

## Быстрый запуск

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/python -m viruswall status
.venv/bin/python -m viruswall gui
```

В Windows используйте `.venv\Scripts\python.exe` вместо `.venv/bin/python`. Команда `gui` открывает отдельное desktop-окно VirusWall на Qt; браузер и веб-сервер не используются. Данные по умолчанию хранятся в `~/.viruswall`; другое расположение задаётся `--data-dir PATH` перед командой.

При первом запуске база содержит только безвредную тестовую сигнатуру EICAR. Для демонстрации собственной сигнатуры создайте обычный текстовый файл и добавьте его SHA-256 в базу:

```bash
python -m viruswall signature add <sha256> Lab.Sample --category test
python -m viruswall scan /путь/к/файлу
```

Примеры других команд: `python -m viruswall interfaces`, `python -m viruswall processes`, `python -m viruswall connections`, `python -m viruswall events`, `python -m viruswall quarantine list`. Полный список: `python -m viruswall --help`.

Технические детали: [ARCHITECTURE.md](ARCHITECTURE.md), установка: [INSTALL.md](INSTALL.md), руководство: [USER_GUIDE.md](USER_GUIDE.md), тесты: [TESTING.md](TESTING.md), API: [API.md](API.md), отчёт по работам: [LABS_3_6.md](LABS_3_6.md).
