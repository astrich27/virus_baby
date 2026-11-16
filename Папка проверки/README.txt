ИСПРАВЛЕНИЯ ДЛЯ РЕПОЗИТОРИЯ virus_baby (перед защитой)
========================================================

Проблема: три модуля не импортируются из GitHub-версии, pytest падает на этапе сбора.
Причина: аннотации типов вычисляются при импорте; метод list() внутри классов затеняет
встроенный тип list в аннотациях, а в network.py имя Path не импортировано на уровне модуля.

Состав папки:
  viruswall-fixes.patch  — готовый git-патч (3 модуля + правки COVERAGE.md/TESTING.md)
  signatures_FIXED.py    — исправленный viruswall/signatures.py
  network_FIXED.py       — исправленный viruswall/network.py
  quarantine_FIXED.py   — исправленный viruswall/quarantine.py

Примечание: в текущем main патч уже применён коммитом ba99ac6;
файлы *_FIXED.py оставлены для сверки и истории проверки.

Как применить (вариант 1, рекомендуется):
  cd путь/к/virus_baby
  git apply путь/к/папке/viruswall-fixes.patch

Как применить (вариант 2, вручную):
  скопировать три файла *_FIXED.py в viruswall/ с заменой имён (убрать _FIXED);
  правки COVERAGE.md и TESTING.md внести по патчу.

Проверка перед коммитом:
  python3 -m venv .venv
  .venv/bin/python -m pip install -e '.[test]'
  .venv/bin/python -m pytest -q        # должно быть: 51 passed

Коммит:
  git add -A
  git commit -m "Fix import-time annotation errors (from __future__ import annotations)"
  git push

Патч проверен на чистом клоне GitHub-версии: применяется без конфликтов,
после него 50/51 тестов проходят без системных GUI-библиотек и 51/51 на машине
с графической средой.
