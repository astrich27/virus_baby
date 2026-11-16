# Публичная база сигнатур VirusWall

`signatures.json` — публичная база SHA-256 для VirusWall. Она собрана только из источников, которые разрешают распространение производных данных.

Состав на момент генерации:

| Источник | Уникальных SHA-256 | Категория | Лицензия |
| --- | ---: | --- | --- |
| EICAR | 1 | `test` | стандартный публичный тестовый образец |
| ESET malware-ioc | 6 156 | `malware` | BSD 2-Clause |
| stalkerware-indicators | 3 228 | `stalkerware` | CC BY 4.0 |
| Amnesty International investigations | 270 | `apt` | CC BY 2.0 |
| **Итого после дедупликации** | **9 655** | | |

Файл имеет формат базы VirusWall (`version: 2`), содержит только SHA-256-сигнатуры и не содержит байтовых шаблонов. Имена вида `ESET.<family>`, `Stalkerware.<app>`, `Amnesty.<campaign>` показывают происхождение записи.

## Установка

Перед импортом закройте GUI VirusWall: приложение держит lock каталога данных.

```bash
python tools/import_signatures.py --source data/signatures.json
```

По умолчанию база объединяется с текущей в `~/.viruswall`, а контрольная сумма в `integrity.json` обновляется. Для замены базы целиком:

```bash
python tools/import_signatures.py --source data/signatures.json --replace
```

Другой каталог данных:

```bash
python tools/import_signatures.py --source data/signatures.json --data-dir /path/to/data
```

## Обновление

```bash
python tools/build_signatures.py
```

Скрипт скачивает актуальные списки, удаляет дубликаты и перезаписывает `data/signatures.json`. Требуется сеть; список источников и правила нормализации зафиксированы в `tools/build_signatures.py`.

## Почему здесь нет Sanesecurity

Sanesecurity запрещает копирование и распространение своих сигнатур без разрешения. Поэтому `malwarehash.hsb` и `hackingteam.hsb` не включены в публичную базу. Их можно использовать локально, если это допускают условия правообладателя, но нельзя выкладывать в этот репозиторий.

## Атрибуция и лицензии

### ESET malware-ioc

Источник: <https://github.com/eset/malware-ioc> — файлы `*/samples.sha256`.

Copyright (c) 2014-2018 ESET spol. s r.o.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

### stalkerware-indicators

Источник: <https://github.com/AssoEchap/stalkerware-indicators>, файл `samples.csv`.

Автор: AssoEchap. Лицензия: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

Изменения: значения SHA-256 извлечены из CSV, имена приложений перенесены в поле `name`, данные объединены с другими источниками и дедуплицированы. Значения хэшей не изменены.

### Amnesty International investigations

Источник: <https://github.com/amnestytech/investigations>, файлы `sha256.txt` и `sha256.csv` в каталогах кампаний.

Автор: Amnesty International. Лицензия: [CC BY 2.0](https://creativecommons.org/licenses/by/2.0/).

Изменения: значения SHA-256 извлечены из текстовых файлов, названия кампаний перенесены в поле `name`, данные объединены с другими источниками и дедуплицированы. Значения хэшей не изменены.

## Ограничения

Хэши — это индикаторы, а не гарантия вредоносности. Возможны устаревшие записи и ложные срабатывания. База предоставляется «как есть», без гарантий; решение о блокировке или карантине принимает оператор.
