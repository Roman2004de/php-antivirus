# delement.antivirus

Модуль 1С-Битрикс **«Интеллектуальный поиск вирусов и троянов»**.

Текущий репозиторий больше не содержит самостоятельный CLI-сканер. Корневые `antivirus.php` и `signatures.txt` вынесены в отдельный проект, а здесь развивается устанавливаемый модуль для 1С-Битрикс Marketplace.

## Паспорт модуля

- `MODULE_ID`: `delement.antivirus`
- Псевдоним: `antivirus`
- Версия: `0.0.1`
- Партнер: `Цифровой Элемент`
- Сайт партнера: `https://d-element.ru`
- Язык интерфейса: русский
- Минимальная цель совместимости: PHP 7.4+, с обязательной проверкой на актуальной версии PHP, поддерживаемой Bitrix
- Composer на первом этапе не используется

## Что уже реализовано

- Устанавливаемый skeleton модуля.
- `install/index.php`, `install/version.php`, `include.php`, `options.php`.
- Административные proxy-файлы для `/bitrix/admin`.
- Страницы админки: сканирование, результаты, карантин.
- Настройки через `Bitrix\Main\Config\Option`.
- D7 autoload map для классов модуля.
- Модульный scanner engine в `lib/`.
- Базовые правила детекта: PHP, JavaScript, HTML, Bitrix-specific.
- AJAX actions: `ping`, `start_scan`, `scan_step`, `get_status`, `cancel_scan`.
- Пошаговое сканирование через AJAX.
- Файловые scan sessions в `var/sessions`.
- JSON reports в `var/reports`.
- Results storage через `Delement\Antivirus\Report\ReportManager`.
- Базовая страница просмотра отчетов в `admin/results.php`.
- Smoke-test engine без ядра Bitrix.

## Структура

```text
bitrix/modules/delement.antivirus/
  include.php
  default_option.php
  options.php

  install/
    index.php
    version.php
    admin/
    css/
    js/
    tools/

  admin/
    ajax.php
    menu.php
    scan.php
    results.php
    quarantine.php

  lib/
    Admin/
    Config/
    Detection/
    File/
    Rules/
    Scanner/

  lang/
    ru/

  tests/
    engine_smoke.php

  var/
    reports/
    sessions/
    quarantine/
```

## Scanner Engine

Основной движок находится в `bitrix/modules/delement.antivirus/lib`.

Ключевые классы:

- `Delement\Antivirus\Config\ScanConfig`
- `Delement\Antivirus\Scanner\Scanner`
- `Delement\Antivirus\Scanner\ScanResult`
- `Delement\Antivirus\Scanner\ScanSummary`
- `Delement\Antivirus\Detection\RuleEngine`
- `Delement\Antivirus\Detection\Detector`
- `Delement\Antivirus\File\FileCollector`
- `Delement\Antivirus\File\FileFilter`
- `Delement\Antivirus\File\FileReader`

Движок не пишет HTML, не вызывает `echo`/`exit` и возвращает структурированные результаты, чтобы его можно было использовать из админки, AJAX, cron runner и будущего CLI-wrapper модуля.

## Настройки

В `options.php` доступны:

- путь сканирования;
- профиль чувствительности: `balanced`, `strict`, `paranoid`;
- действие: `report`, `quarantine`, `delete`;
- `dry-run`;
- путь карантина;
- размер порции сканирования;
- максимальный размер файла;
- список исключений.

Пока destructive actions не завершены, удаление без `dry-run` не разрешается сохранять.

## AJAX API

Endpoint:

```text
/bitrix/admin/delement_antivirus_ajax.php
```

Actions:

- `ping`
- `start_scan`
- `scan_step`
- `get_status`
- `cancel_scan`

Каждый запрос проходит проверку авторизации, прав модуля и `bitrix_sessid`.

## Проверки разработки

Проверить синтаксис PHP-файлов модуля:

```bash
php -l bitrix/modules/delement.antivirus/include.php
```

Полный локальный syntax check из PowerShell:

```powershell
$errors = @()
Get-ChildItem -Recurse -Filter *.php -LiteralPath bitrix/modules/delement.antivirus | ForEach-Object {
    $result = & php -l $_.FullName 2>&1
    if ($LASTEXITCODE -ne 0) {
        $errors += [pscustomobject]@{ File = $_.FullName; Output = ($result -join "`n") }
    }
}
if ($errors.Count -gt 0) { $errors | Format-List; exit 1 }
```

Smoke-test engine без Bitrix:

```bash
php bitrix/modules/delement.antivirus/tests/engine_smoke.php
```

Smoke-test хранилища отчетов:

```bash
php bitrix/modules/delement.antivirus/tests/report_storage_smoke.php
```

## Важные ограничения

- Это сигнатурный и rule-based scanner, а не полноценная EDR/AV/WAF-система.
- Автоматическое удаление не должно быть поведением по умолчанию.
- Любые destructive actions должны иметь `dry-run`, проверку прав, `sessid` и явное подтверждение.
- `/upload/` целиком не исключается: PHP-файлы внутри `/upload/` являются важным индикатором компрометации.

## Следующий этап

Ближайшая задача: реализовать полноценное отображение результатов сканирования в `admin/results.php`, фильтры и экспорт JSON из сохраненных reports.
