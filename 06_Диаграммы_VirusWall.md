# Диаграммы архитектуры VirusWall

## Компонентная архитектура

```mermaid
flowchart TB
    UI[GUI PySide6 / CLI] --> CORE[Центральный модуль core.py]
    OWNER[(Каталог данных: config / базы / журнал / карантин)] -.-> CORE
    OS[Операционная система] --> RT[watchdog: события ФС]
    OS --> PROC[psutil: процессы и соединения]
    OS --> NET[Scapy: пакеты / PCAP]
    RT --> CORE
    PROC --> BEH[Поведенческий анализ behavior_templates]
    CORE --> SCAN[Сканер scanner.py]
    SCAN --> SIG[Сигнатуры: SHA-256/MD5/шаблоны]
    SCAN --> HEU[Эвристика]
    CORE --> POL[Политика: observe / notify / quarantine]
    POL --> Q[Карантин AES-256-GCM]
    CORE --> JOURNAL[Журнал: хеш-цепочка]
    CORE --> UPD[Обновления Ed25519]
    UPD --> DB[(База сигнатур JSON)]
    CORE --> SELF[Самозащита: InstanceLock, IntegrityGuard, doctor]
    JOURNAL --> NOTIFY[Уведомления GUI/ОС]
```

## Последовательность обнаружения

```mermaid
sequenceDiagram
    participant OS as ОС
    participant M as Монитор watchdog
    participant S as Ядро
    participant C as Сканер
    participant D as Детекторы
    participant Q as Карантин
    participant L as Журнал
    participant U as Пользователь
    OS->>M: Событие записи файла
    M->>S: Событие (дедупликация по путь+mtime)
    S->>L: Запись file_event
    S->>C: Проверить файл
    C->>D: SHA-256/MD5, шаблоны, эвристика
    D-->>C: Вердикт и причины
    C-->>S: ScanResult
    alt политика quarantine и режим armed
        S->>Q: Изолировать AES-256-GCM
    else политика notify
        S->>U: Уведомление
    else политика observe
        S->>L: Только журнал
    end
    S->>L: threat_detected + reaction_ms
    L-->>U: Уведомление GUI
```

## Развёртывание

```mermaid
flowchart LR
    subgraph Windows
      WG[GUI/CLI Python] --> WRT[watchdog ReadDirectoryChangesW]
      WPS[psutil] --> WG
    end
    subgraph Linux
      LG[GUI/CLI Python] --> LRT[watchdog inotify]
      LPS[psutil] --> LG
    end
    subgraph macOS
      MG[GUI/CLI Python] --> MRT[watchdog kqueue/FSEvents]
      MPS[psutil] --> MG
    end
    WG --> COMMON[Общее ядро VirusWall: сканер / карантин / журнал / обновления]
    LG --> COMMON
    MG --> COMMON
    COMMON --> STORE[(Каталог данных 0700)]
    NOTE[Служба/драйвер: точка расширения, не реализовано] -.-> COMMON
```
