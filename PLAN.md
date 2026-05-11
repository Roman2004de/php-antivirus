# PHP Antivirus — Актуализированный план рефакторинга и выхода в Production

> Обновлённый roadmap проекта на основе текущего состояния исходного кода.
>
> Текущая стадия проекта: **advanced MVP / pre-production refactor**.

---

# 📌 Текущее состояние проекта

## Уже реализовано

### Основной функционал

- CLI-антивирус на PHP
- Рекурсивное сканирование директорий
- Сигнатурный анализ
- Поддержка внешнего файла сигнатур
- Обработка больших файлов чанками
- Пропуск бинарных файлов
- Фильтрация файлов по расширениям
- JSON output
- Verbose / short режимы
- Quarantine mode
- Логирование
- Exit codes
- Базовый detection engine

---

## Техническое состояние

### Сильные стороны

- Проект уже является рабочим CLI utility
- Архитектура текущего скрипта понятна
- Есть foundation для дальнейшего развития
- CLI интерфейс уже usable
- Реализованы production-like режимы

---

### Основные проблемы

- Весь проект находится в одном файле
- Отсутствует модульная архитектура
- Нет findings model
- Нет scoring engine
- Нет whitelist
- Нет полноценного rule engine
- Нет profiles/config system
- Нет тестов
- Нет performance cache
- Нет многопоточности
- Нет explainability layer
- Высокий риск false positives

---

# 🎯 Цель рефакторинга

Преобразовать проект из utility-level scanner в production-ready malware scanner:

- расширяемый
- explainable
- modular
- configurable
- scalable
- безопасный
- пригодный для CI/CD и automation

---

# 🧱 Целевая архитектура

```text
project/
│
├── antivirus.php
│
├── src/
│   ├── Scanner/
│   ├── Engine/
│   ├── Rules/
│   ├── Heuristics/
│   ├── Quarantine/
│   ├── Reporting/
│   ├── Profiles/
│   ├── Whitelist/
│   └── Utils/
│
├── config/
│   ├── rules/
│   ├── profiles/
│   ├── whitelist/
│   └── settings.php
│
├── var/
│   ├── logs/
│   ├── cache/
│   ├── quarantine/
│   └── reports/
│
├── tests/
│
└── README.md
```

---

# 🧠 Целевая модель анализа

```text
rules
   ↓
findings
   ↓
heuristics
   ↓
scoring
   ↓
verdict
   ↓
actions
```

---

# 📊 Целевая структура результата

```json
{
  "file": "index.php",
  "status": "suspicious",
  "score": 12,
  "findings": [],
  "categories": [],
  "heuristics": [],
  "verdict": "high_risk"
}
```

---

# 🚦 Статусы проверки

| Status | Описание |
|---|---|
| clean | угроз не найдено |
| skipped | файл пропущен |
| low_risk | слабые сигнатуры |
| suspicious | подозрительный файл |
| malicious | вредоносный файл |
| error | ошибка обработки |

---

# ⚖️ Модель scoring

| Indicator | Score |
|---|---|
| eval() | +5 |
| system()/exec() | +4 |
| base64_decode | +2 |
| gzinflate | +2 |
| dynamic include | +3 |
| obfuscation chain | +5 |
| webshell signature | +8 |

---

# 🧪 Профили сканирования

| Profile | Описание |
|---|---|
| balanced | стандартный режим |
| strict | минимизация false negatives |
| paranoid | aggressive detection |
| ci | machine-friendly output |

---

# 📂 Whitelist Model

Поддержка:

- paths
- regex patterns
- hashes
- trusted vendors
- file exceptions
- directory exclusions

---

# ⚙️ Режимы работы

| Mode | Описание |
|---|---|
| report | только отчет |
| quarantine | карантин |
| delete | удаление |
| dry-run | тестовый режим |
| ci | режим CI/CD |

---

# 🚧 Актуализированный Roadmap

---

# Phase 1 — Архитектурный рефакторинг

> Цель: разделить monolith и стабилизировать ядро.

## 1. Разделение проекта на модули

### Tasks

- вынести scanner logic
- вынести cli parser
- вынести logging
- вынести quarantine
- создать src/
- создать базовые классы

### Status

⬜ NOT STARTED

---

## 2. Rule Engine

### Tasks

- нормализовать signatures
- categories
- severity
- metadata
- отдельные rules files

### Status

🟨 PARTIALLY IMPLEMENTED

---

## 3. Findings Model

### Tasks

- findings entity
- evidence
- offsets
- matched rule
- severity
- explanation

### Status

⬜ NOT STARTED

---

## 4. Regex Refactor

### Tasks

- убрать dangerous regex
- минимизировать false positives
- оптимизировать patterns
- grouped patterns
- benchmark regex

### Status

🟨 PARTIALLY IMPLEMENTED

---

# Phase 2 — Detection Intelligence

> Цель: сделать scanner explainable и reliable.

## 5. Scoring Engine

### Tasks

- weighted scoring
- thresholds
- verdict system
- profile-aware scoring

### Status

⬜ NOT STARTED

---

## 6. Категории угроз

### Categories

- webshell
- obfuscation
- downloader
- phishing
- persistence
- malware
- backdoor
- crypto miner

### Status

⬜ NOT STARTED

---

## 7. Heuristics Engine

### Tasks

- obfuscation chains
- entropy checks
- suspicious nesting
- dynamic execution detection
- encoded payload detection

### Status

🟨 BASIC IMPLEMENTATION EXISTS

---

## 8. Whitelist System

### Tasks

- whitelist config
- vendor exclusions
- trusted hashes
- path ignore
- regex exclusions

### Status

⬜ NOT STARTED

---

# Phase 3 — CLI и Reporting

> Цель: production-grade UX и automation.

## 9. CLI Refactor

### Tasks

- improved help
- subcommands
- validation
- profile selection
- interactive flags

### Status

🟩 BASIC IMPLEMENTATION READY

---

## 10. Reporting System

### Tasks

- HTML reports
- statistics
- grouped findings
- timeline
- severity summary
- machine-readable reports

### Status

🟨 JSON READY

---

## 11. Quarantine System

### Tasks

- metadata
- restore support
- integrity validation
- quarantine index

### Status

🟩 BASIC IMPLEMENTATION READY

---

## 12. Стандартизация Exit Codes

### Tasks

- stable CI codes
- documented exit map
- automation compatibility

### Status

🟩 IMPLEMENTED

---

# Phase 4 — Производительность и масштабируемость

> Цель: production performance.

## 13. Оптимизация производительности

### Tasks

- streaming scan
- smart IO
- async logging
- optimized traversal
- memory profiling

### Status

🟨 PARTIALLY IMPLEMENTED

---

## 14. Incremental Cache

### Tasks

- file hash cache
- modified time cache
- incremental scan
- cache invalidation

### Status

⬜ NOT STARTED

---

## 15. Параллельное сканирование

### Tasks

- pcntl_fork
- worker pool
- parallel traversal
- process-safe logging

### Status

⬜ NOT STARTED

---

# Phase 5 — Production Readiness

> Цель: довести проект до production-grade уровня.

## 16. Configuration System

### Tasks

- global config
- profiles config
- rules config
- runtime overrides

### Status

⬜ NOT STARTED

---

## 17. Тестирование

### Tasks

- unit tests
- integration tests
- malware fixtures
- regression tests
- false positive tests

### Status

⬜ NOT STARTED

---

## 18. CI/CD Integration

### Tasks

- GitHub Actions
- static analysis
- automated tests
- release artifacts

### Status

⬜ NOT STARTED

---

## 19. Security Hardening

### Tasks

- safe path handling
- sandboxing
- symlink protection
- secure quarantine
- log sanitization

### Status

⬜ NOT STARTED

---

## 20. Документация

### Tasks

- architecture docs
- rule writing guide
- developer docs
- API docs
- operational docs

### Status

🟨 README EXISTS

---

# 📈 Общий прогресс проекта

| Направление | Progress |
|---|---|
| Core Scanner | 80% |
| CLI | 70% |
| Detection | 45% |
| Architecture | 20% |
| Reporting | 40% |
| Performance | 25% |
| Production Readiness | 10% |

---

# 🧭 Приоритеты разработки

## Priority 1 — Critical

1. Modular architecture
2. Findings model
3. Scoring engine
4. Whitelist
5. Rule engine normalization

---

## Priority 2 — Important

6. Heuristics engine
7. Reporting system
8. Config/profiles
9. Tests

---

## Priority 3 — Scaling

10. Cache
11. Parallel scanning
12. CI/CD
13. Security hardening

---

# 📍 Текущая стадия проекта

```text
WORKING MVP
    ↓
ARCHITECTURE REFACTOR
    ↓
DETECTION ENGINE
    ↓
PRODUCTION HARDENING
    ↓
PRODUCTION READY
```

---

# 🏁 Рекомендуемый следующий шаг

## Immediate Next Action

Начать с:

### Step 1

Создать modular architecture:

- src/
- Scanner/
- Engine/
- Rules/
- Reporting/
- Quarantine/

И вынести core scanner logic из monolith-файла.

Это откроет возможность для всего дальнейшего рефакторинга.

