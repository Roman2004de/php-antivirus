# Техническое задание  
# Модуль антивирусного сканера для 1С-Битрикс Marketplace

**Рабочее название модуля:** `rt.antivirus`  
**Назначение:** production-oriented модуль антивирусного сканирования для сайтов на 1С-Битрикс  
**База для разработки:** текущий CLI/PHP antivirus middleware + анализ референсного модуля `sng.secure`  
**Целевая публикация:** 1С-Битрикс Marketplace  
**Минимальная версия PHP:** 7.4  
**Composer:** не использовать на первом этапе  
**Основной язык интерфейса:** русский  
**Архитектурный стиль:** D7-compatible, модульная структура, без копирования кода конкурента

---

## 1. Назначение документа

Этот документ является техническим заданием для разработки нового модуля антивируса под платформу 1С-Битрикс.

Документ описывает:

- цели продукта;
- архитектуру модуля;
- структуру файлов;
- административный интерфейс;
- движок сканирования;
- хранение настроек и результатов;
- карантин;
- dry-run;
- cron/agent-режим;
- требования безопасности;
- требования для подготовки к Marketplace;
- пошаговый план работ для реализации через Codex.

---

## 2. Цель проекта

Создать модуль для 1С-Битрикс, который позволит администратору сайта:

- запускать проверку файлов сайта из административной панели;
- видеть прогресс сканирования;
- получать список подозрительных файлов;
- понимать причины срабатывания;
- безопасно помещать файлы в карантин;
- запускать проверку по cron;
- использовать dry-run перед destructive actions;
- настраивать исключения;
- использовать профили чувствительности;
- получать отчеты для аудита и автоматизации.

Модуль должен быть не просто копией CLI-скрипта, а полноценной Bitrix-интеграцией вокруг общего scanner engine.

---

## 3. Что берем из референсного модуля

Из конкурентного модуля `sng.secure` берем **идеи и паттерны интеграции**, но не копируем исходный код.

### 3.1. Полезные идеи

1. **Админская страница настроек**
   - путь сканирования;
   - список исключений;
   - кнопка запуска проверки;
   - блок вывода результатов.

2. **AJAX-пошаговое сканирование**
   - сканирование не выполняется одним длинным запросом;
   - используется порционный подход;
   - фронтенд вызывает backend повторно до завершения.

3. **Исключения по умолчанию**
   - cache-директории;
   - managed cache;
   - директория самого модуля.

4. **Cron/tool runner**
   - отдельный PHP-файл в `/bitrix/tools/...`;
   - возможность запуска проверки вне браузера.

5. **Простая интеграция с административным интерфейсом**
   - proxy-файлы в `/bitrix/admin/`;
   - `options.php`;
   - `install/index.php`;
   - `install/version.php`;
   - `lang/ru/`.

### 3.2. Что НЕ берем

Не переносить:

- чужой код;
- чужие названия классов;
- чужие regex как есть;
- хранение результатов в `$_SESSION` как основную модель;
- unsafe regex сборку для исключений;
- старый процедурный стиль как основу;
- AJAX без нормальной проверки прав и sessid;
- хранение больших результатов в `COption`.

---

## 4. Что берем из нашего CLI/middleware антивируса

Из текущего CLI-решения берем как основу scanner engine:

- рекурсивное сканирование;
- сигнатурный анализ;
- безопасное чтение файлов;
- проверку бинарных файлов;
- обработку больших файлов;
- runtime error tracking;
- exit/status модель;
- quarantine metadata;
- JSON-friendly reporting;
- dry-run концепцию;
- валидацию regex;
- deduplicate detected files.

### 4.1. Что нужно переработать перед интеграцией

Текущий CLI-код нужно постепенно вынести в reusable-классы:

- `Scanner`
- `FileCollector`
- `FileFilter`
- `FileReader`
- `Detector`
- `RuleEngine`
- `SignatureLoader`
- `Whitelist`
- `QuarantineManager`
- `ReportManager`

Цель: один и тот же движок должен использоваться:

- из Bitrix admin UI;
- из AJAX endpoint;
- из cron/tool runner;
- потенциально из CLI.

---

## 5. Общие требования к модулю 1С-Битрикс

Модуль должен соответствовать стандартной структуре модулей 1С-Битрикс:

- наличие `install/index.php`;
- наличие `install/version.php`;
- наличие `include.php`;
- наличие `options.php`;
- наличие `lang/ru/`;
- корректная регистрация модуля;
- корректное удаление модуля;
- использование административных proxy-файлов;
- проверка прав доступа администратора;
- использование `bitrix_sessid`;
- отсутствие прямого небезопасного выполнения пользовательского ввода;
- отсутствие внешних зависимостей без необходимости;
- работа без Composer на первом этапе;
- совместимость с PHP 7.4.

Перед публикацией в Marketplace обязательно дополнительно сверить модуль с актуальным чеклистом 1С-Битрикс Marketplace, так как требования публикации могут меняться.

---

## 6. Идентификатор модуля

Предлагаемый module id:

```text
rt.antivirus
```

Альтернативы:

```text
roman.antivirus
webantivirus.scanner
```

Рекомендуется использовать короткий vendor prefix + понятное имя модуля.

---

## 7. Целевая структура модуля

```text
bitrix/modules/rt.antivirus/
  include.php
  options.php

  install/
    index.php
    version.php
    admin/
      rt_antivirus_scan.php
      rt_antivirus_results.php
      rt_antivirus_quarantine.php
    tools/
      scan.php
    js/
      scanner.js
    css/
      admin.css
    images/
      icon.png

  admin/
    scan.php
    ajax.php
    results.php
    quarantine.php

  lib/
    Config/
      ModuleConfig.php

    Scanner/
      Scanner.php
      ScanSession.php
      ScanCursor.php
      ScanResult.php
      ScanSummary.php

    File/
      FileCollector.php
      FileFilter.php
      FileReader.php
      FileTypeDetector.php

    Detection/
      Detector.php
      RuleEngine.php
      SignatureLoader.php
      Finding.php
      Verdict.php
      Severity.php

    Rules/
      php.php
      javascript.php
      html.php
      bitrix.php

    Whitelist/
      Whitelist.php
      WhitelistRule.php

    Quarantine/
      QuarantineManager.php
      QuarantineItem.php

    Report/
      ReportManager.php
      JsonReportWriter.php

    Admin/
      AjaxController.php
      Permission.php

    Internals/
      ScanTable.php
      FindingTable.php
      QuarantineTable.php

  lang/
    ru/
      install/index.php
      options.php
      admin/scan.php
      admin/results.php
      admin/quarantine.php

  var/
    reports/
    quarantine/
    sessions/
```

---

## 8. Архитектурная модель

### 8.1. Главная модель

```text
Bitrix Admin UI
      ↓
AJAX Controller
      ↓
Scan Session
      ↓
Scanner
      ↓
FileCollector → FileFilter → FileReader
      ↓
Detector → RuleEngine → Findings
      ↓
Score → Verdict
      ↓
Report / DB / Quarantine
```

### 8.2. Принцип

Сканер не должен быть завязан напрямую на UI.

Должен существовать общий scanner engine, который можно вызвать из:

- админки;
- AJAX;
- cron;
- CLI.

---

## 9. Основные сущности

### 9.1. ScanSession

Описывает одну сессию сканирования.

Поля:

- `scan_id`
- `started_at`
- `finished_at`
- `status`
- `path`
- `profile`
- `action`
- `dry_run`
- `processed_files`
- `total_files_estimated`
- `found_total`
- `runtime_errors`
- `cursor`
- `created_by`

Статусы:

- `created`
- `running`
- `paused`
- `finished`
- `failed`
- `cancelled`

### 9.2. ScanResult

Результат проверки одного файла.

Поля:

- `scan_id`
- `file_path`
- `file_hash`
- `status`
- `score`
- `severity`
- `findings`
- `action`
- `error`

Статусы файла:

- `clean`
- `skipped`
- `low_risk`
- `suspicious`
- `malicious`
- `error`

### 9.3. Finding

Отдельная находка.

Поля:

- `signature_id`
- `name`
- `category`
- `severity`
- `score`
- `offset`
- `excerpt`
- `target`
- `rule_type`

### 9.4. QuarantineItem

Файл в карантине.

Поля:

- `id`
- `original_path`
- `quarantine_path`
- `sha256`
- `created_at`
- `scan_id`
- `metadata`
- `restore_status`

---

## 10. Детект и правила

### 10.1. Подход

Уходим от модели:

```text
regex matched -> infected
```

Переходим к модели:

```text
rules -> findings -> score -> verdict
```

### 10.2. Категории правил

- `php_code_execution`
- `php_obfuscation`
- `webshell_behavior`
- `javascript_injection`
- `phishing_markup`
- `bitrix_specific`
- `filesystem_abuse`
- `network_abuse`

### 10.3. Bitrix-specific правила

Обязательные правила для первой версии:

1. PHP-файл внутри `/upload/`
2. Подозрительный код в `/bitrix/php_interface/init.php`
3. Подозрительные include/require из `/upload/`
4. `$USER->Authorize(...)` с жестко заданным ID
5. Подозрительные изменения `.access.php`
6. Опасные обработчики событий
7. Подозрительные агенты
8. `eval/assert/create_function` с данными из `$_GET/$_POST/$_REQUEST`
9. `php://filter`
10. длинные base64-like строки
11. скрытые переменные через hex notation
12. `file_put_contents()` PHP-кода
13. `move_uploaded_file()` в исполняемые расширения

---

## 11. Scoring

### 11.1. Пример весов

| Признак | Score |
|---|---:|
| `eval()` | 5 |
| `assert()` | 4 |
| `base64_decode()` | 2 |
| `system/exec/shell_exec` | 5 |
| PHP in `/upload/` | 8 |
| `$USER->Authorize(ID)` | 8 |
| `php://filter` | 5 |
| long base64-like string | 3 |
| `file_put_contents` PHP payload | 6 |

### 11.2. Комбинации

Комбинационные бонусы:

| Комбинация | Extra Score |
|---|---:|
| `base64_decode + eval` | +5 |
| `$_POST + exec` | +5 |
| `php://input + file_put_contents` | +6 |
| PHP in upload + obfuscation | +5 |
| Bitrix auth backdoor + request input | +7 |

---

## 12. Профили детекта

### 12.1. balanced

Основной production-режим.

- меньше false positives;
- выше порог malicious;
- подходит для регулярного запуска.

### 12.2. strict

Для аудита.

- больше предупреждений;
- ниже пороги;
- шире набор правил.

### 12.3. paranoid

Для incident response.

- максимальная чувствительность;
- много шума;
- только для ручного анализа.

### 12.4. Пороговые значения

```php
balanced:
  suspicious: 4
  malicious: 8

strict:
  suspicious: 3
  malicious: 6

paranoid:
  suspicious: 2
  malicious: 5
```

---

## 13. Whitelist и исключения

### 13.1. Исключения по умолчанию

```text
/bitrix/cache/
/bitrix/managed_cache/
/bitrix/stack_cache/
/bitrix/html_pages/
/upload/resize_cache/
/bitrix/modules/rt.antivirus/
```

Важно: `/upload/` целиком исключать нельзя.  
PHP-файлы в `/upload/` являются важным индикатором взлома.

### 13.2. Типы whitelist

- по пути;
- по regex пути;
- по hash;
- по signature id;
- по сочетанию file + signature id.

---

## 14. Административный интерфейс

### 14.1. Страница настроек

Файл:

```text
options.php
```

Настройки:

- путь сканирования по умолчанию;
- профиль детекта;
- режим действия:
  - report;
  - quarantine;
  - delete;
- dry-run;
- quarantine path;
- exclude paths;
- max file size;
- scan batch size;
- email notifications;
- cron token;
- включение/отключение категорий правил.

### 14.2. Страница сканирования

Файл:

```text
admin/scan.php
```

Функции:

- запуск сканирования;
- progress bar;
- количество проверенных файлов;
- количество найденных угроз;
- текущий файл;
- кнопка stop/cancel;
- ссылка на результаты.

### 14.3. Страница результатов

Файл:

```text
admin/results.php
```

Таблица:

- время;
- файл;
- verdict;
- score;
- severity;
- category;
- signature;
- excerpt;
- action;
- кнопки:
  - открыть файл;
  - отправить в карантин;
  - пометить безопасным;
  - добавить в whitelist;
  - экспортировать отчет.

### 14.4. Страница карантина

Файл:

```text
admin/quarantine.php
```

Функции:

- список файлов в карантине;
- original path;
- hash;
- дата;
- restore;
- delete permanently;
- view metadata.

---

## 15. AJAX API

### 15.1. Endpoint

```text
/bitrix/admin/rt_antivirus_ajax.php
```

### 15.2. Actions

- `start_scan`
- `scan_step`
- `cancel_scan`
- `get_status`
- `get_results`
- `quarantine_file`
- `restore_file`
- `add_whitelist`

### 15.3. Требования безопасности

Каждый запрос должен проверять:

- авторизацию;
- права доступа к модулю;
- `check_bitrix_sessid()`;
- корректность action;
- валидность пути;
- принадлежность пути document root;
- отсутствие path traversal.

### 15.4. Пример ответа scan_step

```json
{
  "status": "progress",
  "scan_id": "20260527_abc123",
  "processed": 150,
  "found": 3,
  "runtime_errors": 0,
  "next_cursor": "150",
  "current_file": "/local/php_interface/init.php"
}
```

---

## 16. Хранение данных

### 16.1. Настройки

На MVP можно использовать:

```php
\Bitrix\Main\Config\Option
```

Хранить:

- default path;
- profile;
- action;
- dry_run;
- quarantine_path;
- exclude paths;
- max file size;
- batch size.

### 16.2. Результаты

Не хранить большие результаты в `COption`.

Использовать:

- ORM-таблицы;
- JSON reports в `var/reports/`;
- или комбинированный подход.

### 16.3. Таблицы

#### `rt_antivirus_scan`

- `ID`
- `SCAN_ID`
- `DATE_START`
- `DATE_FINISH`
- `STATUS`
- `PATH`
- `PROFILE`
- `ACTION`
- `DRY_RUN`
- `PROCESSED`
- `FOUND`
- `RUNTIME_ERRORS`

#### `rt_antivirus_finding`

- `ID`
- `SCAN_ID`
- `FILE_PATH`
- `FILE_HASH`
- `STATUS`
- `SCORE`
- `SEVERITY`
- `SIGNATURE_ID`
- `CATEGORY`
- `EXCERPT`
- `CREATED_AT`

#### `rt_antivirus_quarantine`

- `ID`
- `SCAN_ID`
- `ORIGINAL_PATH`
- `QUARANTINE_PATH`
- `SHA256`
- `CREATED_AT`
- `RESTORED`
- `RESTORED_AT`

---

## 17. Карантин

### 17.1. Требования

Карантин должен:

- не перезаписывать файлы;
- использовать уникальные имена;
- считать SHA256;
- сохранять metadata JSON;
- поддерживать dry-run;
- поддерживать restore;
- поддерживать permanent delete;
- логировать действия.

### 17.2. Путь

```text
/bitrix/modules/rt.antivirus/var/quarantine/
```

или настраиваемый путь вне web-root.

Рекомендуется по возможности хранить карантин вне публичной директории.

---

## 18. Dry-run

### 18.1. Назначение

Dry-run — режим, в котором модуль показывает, что было бы сделано, но не меняет файловую систему.

### 18.2. Поведение

В dry-run:

- сканирование выполняется полностью;
- findings формируются;
- quarantine/delete не выполняются;
- в результат пишется planned_action;
- файл остается на месте.

### 18.3. UI

В интерфейсе обязательно показать предупреждение:

```text
Dry-run включен: файлы не будут перемещены или удалены.
```

---

## 19. Cron / tools runner

### 19.1. Файл

```text
/bitrix/tools/rt.antivirus/scan.php
```

### 19.2. Назначение

Позволяет запускать проверку из cron.

### 19.3. Пример

```bash
php /path/to/site/bitrix/tools/rt.antivirus/scan.php --profile=balanced --json
```

### 19.4. Возможности

- запуск по cron;
- сохранение отчета;
- отправка email уведомления;
- exit codes;
- JSON output.

---

## 20. Права доступа

Реализовать уровни:

- `D` — доступ запрещен;
- `R` — просмотр результатов;
- `W` — запуск сканирования;
- `X` — destructive actions: quarantine/delete/restore.

Любой AJAX/action должен проверять права.

---

## 21. Безопасность

Обязательные требования:

- проверять sessid;
- проверять права;
- валидировать пути;
- запрещать path traversal;
- запрещать сканирование вне разрешенной зоны без явного разрешения;
- не выполнять найденный код;
- не показывать большие фрагменты вредоносного файла без escaping;
- не хранить quarantine в публичном доступе без защиты;
- логировать destructive actions;
- не использовать пользовательские regex без валидации;
- не собирать regex из пользовательского пути без `preg_quote`.

---

## 22. Marketplace readiness

Перед публикацией:

- модуль должен устанавливаться/удаляться без ошибок;
- все файлы должны иметь корректную структуру;
- все языковые строки должны быть вынесены в `lang/ru`;
- не должно быть debug output;
- не должно быть hardcoded абсолютных путей;
- не должно быть небезопасных прямых SQL без ORM/connection escaping;
- административные страницы должны проверять права;
- AJAX должен проверять sessid;
- uninstall должен удалять proxy-файлы;
- uninstall должен предлагать сохранить или удалить данные;
- модуль должен иметь документацию;
- должен быть changelog;
- должен быть version.php;
- желательно подготовить демо-скриншоты интерфейса.

---

## 23. MVP scope

### В MVP входит

- installable module;
- settings page;
- AJAX scan;
- progress;
- scanner engine integration;
- simple signatures;
- Bitrix-specific rules;
- results table;
- JSON report;
- quarantine;
- dry-run;
- default exclusions;
- basic whitelist;
- cron runner.

### В MVP не входит

- ML;
- YARA;
- parallel scanning;
- cloud signature updates;
- archive unpacking;
- CMS auto-healing;
- automatic malware removal without confirmation.

---

## 24. Этапы разработки

## Этап 1. Installable skeleton

### Цель

Создать устанавливаемый модуль.

### Задачи Codex

1. Создать структуру `rt.antivirus`.
2. Создать `install/index.php`.
3. Создать `install/version.php`.
4. Создать `include.php`.
5. Создать `options.php`.
6. Создать admin proxy files.
7. Реализовать `DoInstall()` и `DoUninstall()`.
8. Проверить установку/удаление.

### Acceptance criteria

- модуль появляется в списке модулей;
- модуль устанавливается;
- модуль удаляется;
- страница настроек открывается.

---

## Этап 2. Settings UI

### Цель

Сделать настройки модуля.

### Задачи Codex

1. Добавить форму настроек.
2. Использовать `Option`.
3. Добавить поля:
   - scan path;
   - profile;
   - action;
   - dry-run;
   - quarantine path;
   - exclusions;
   - batch size.
4. Проверять sessid.
5. Сохранять настройки.

### Acceptance criteria

- настройки сохраняются;
- настройки загружаются;
- поля валидируются.

---

## Этап 3. Scanner engine extraction

### Цель

Перенести middleware scanner в reusable engine.

### Задачи Codex

1. Создать `lib/Scanner/Scanner.php`.
2. Создать `FileCollector`.
3. Создать `FileFilter`.
4. Создать `FileReader`.
5. Создать `Detector`.
6. Создать `RuleEngine`.
7. Создать `SignatureLoader`.
8. Создать DTO для ScanResult и Finding.
9. Перенести текущие regex.
10. Добавить Bitrix-specific rules.

### Acceptance criteria

- scanner работает без UI;
- scanner возвращает структурированный результат;
- scanner не вызывает echo/exit напрямую.

---

## Этап 4. AJAX scan

### Цель

Сделать порционное сканирование.

### Задачи Codex

1. Создать `admin/ajax.php`.
2. Реализовать actions:
   - start_scan;
   - scan_step;
   - get_status;
   - cancel_scan.
3. Ввести scan session.
4. Сохранять cursor.
5. Возвращать JSON.

### Acceptance criteria

- scan не падает по timeout;
- UI получает progress;
- scan можно завершить.

---

## Этап 5. Results UI

### Цель

Показать результаты сканирования.

### Задачи Codex

1. Создать `admin/results.php`.
2. Реализовать таблицу findings.
3. Добавить фильтры.
4. Добавить экспорт JSON.
5. Добавить actions.

### Acceptance criteria

- результаты доступны после скана;
- видно file, score, severity, finding;
- можно отфильтровать malicious/suspicious.

---

## Этап 6. Quarantine

### Цель

Сделать полноценный карантин.

### Задачи Codex

1. Создать `QuarantineManager`.
2. Реализовать quarantine.
3. Реализовать dry-run.
4. Реализовать restore.
5. Реализовать metadata JSON.
6. Создать admin/quarantine.php.

### Acceptance criteria

- файлы не перезаписываются;
- metadata создается;
- restore работает;
- dry-run не меняет файловую систему.

---

## Этап 7. Whitelist

### Цель

Снизить false positives.

### Задачи Codex

1. Создать `Whitelist`.
2. Реализовать path whitelist.
3. Реализовать regex whitelist.
4. Реализовать hash whitelist.
5. Реализовать signature exception.
6. Добавить UI actions.

### Acceptance criteria

- файл можно добавить в whitelist;
- конкретную сигнатуру можно исключить для файла;
- whitelist учитывается при scan.

---

## Этап 8. Cron runner

### Цель

Добавить запуск по расписанию.

### Задачи Codex

1. Создать `install/tools/scan.php`.
2. Реализовать CLI args.
3. Подключить Bitrix prolog.
4. Запускать scanner.
5. Сохранять отчет.
6. Возвращать exit code.

### Acceptance criteria

- scan запускается из CLI;
- отчет сохраняется;
- exit code корректный.

---

## Этап 9. Marketplace polish

### Цель

Подготовить модуль к публикации.

### Задачи Codex

1. Вынести тексты в lang.
2. Убрать debug.
3. Проверить install/uninstall.
4. Проверить права.
5. Проверить sessid.
6. Проверить пути.
7. Подготовить README.
8. Подготовить changelog.
9. Подготовить screenshots.

### Acceptance criteria

- модуль готов к ручной проверке перед Marketplace.

---

## 25. Codex working rules

При работе через Codex соблюдать правила:

1. Один этап — один pull request.
2. Не смешивать install skeleton и scanner engine.
3. После каждого этапа запускать syntax check.
4. Не добавлять Composer.
5. Не копировать код из референса.
6. Использовать namespace `Rt\Antivirus`.
7. Все публичные действия защищать правами и sessid.
8. Scanner не должен напрямую писать HTML.
9. UI не должен содержать detector logic.
10. Любое destructive action должно иметь dry-run и подтверждение.

---

## 26. Первый набор задач для Codex

### Task 1

Создать skeleton Bitrix module `rt.antivirus`.

### Task 2

Создать `options.php` с сохранением настроек через `Option`.

### Task 3

Создать admin page `scan.php` с кнопкой запуска и подключением JS.

### Task 4

Создать AJAX controller с action `ping` и `start_scan`.

### Task 5

Вынести scanner engine из CLI в классы без зависимости от Bitrix UI.

### Task 6

Добавить простую scan_step итерацию по файлам.

### Task 7

Добавить results storage.

### Task 8

Добавить quarantine manager.

---

## 27. Definition of Done для MVP

MVP считается готовым, если:

- модуль устанавливается;
- настройки сохраняются;
- сканирование запускается из админки;
- прогресс виден;
- результаты сохраняются;
- findings отображаются;
- quarantine работает;
- dry-run работает;
- cron runner работает;
- права проверяются;
- sessid проверяется;
- uninstall корректно очищает proxy-файлы;
- документация готова.

---

## 28. Основной принцип продукта

Модуль должен быть безопасным в первую очередь.

Поэтому порядок действий:

```text
scan -> explain -> review -> quarantine -> restore/delete manually
```

Автоматическое удаление без ручного подтверждения не должно быть поведением по умолчанию.

---

## 29. Стартовая реализация

Следующий практический шаг:

```text
Этап 1 — Installable skeleton
```

После него:

```text
Этап 2 — Settings UI
```

Только затем подключать scanner engine.

