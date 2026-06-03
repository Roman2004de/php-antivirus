# delement.antivirus

Модуль 1С-Битрикс **«Антивирус: поиск вирусов и троянов»**.

Текущий репозиторий больше не содержит самостоятельный CLI-сканер. Корневые `antivirus.php` и `signatures.txt` вынесены в отдельный проект, а здесь развивается устанавливаемый модуль для 1С-Битрикс Marketplace.

## Паспорт модуля

- `MODULE_ID`: `delement.antivirus`
- Псевдоним: `antivirus`
- Версия: `0.0.1`
- Партнер: `Цифровой Элемент`
- Сайт партнера: `https://d-element.ru`
- Язык интерфейса: русский и английский
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
- Поддержка внешнего файла regex-сигнатур с добавлением к встроенным правилам.
- Профили сканирования Bitrix: `quick`, `standard`, `deep`.
- AJAX actions: `ping`, `start_scan`, `scan_step`, `get_status`, `cancel_scan`.
- Пошаговое сканирование через AJAX.
- Защита от параллельных сканов через marker активной сессии и lock-файл.
- Файловые scan sessions в runtime-каталоге `/bitrix/tmp/delement.antivirus/sessions`.
- JSON reports в runtime-каталоге `/bitrix/tmp/delement.antivirus/reports`.
- Частичные JSON reports для отмененных сканирований.
- Results storage через `Delement\Antivirus\Report\ReportManager`.
- Страница просмотра отчетов в `admin/results.php` на штатном Bitrix `CAdminList`.
- Отдельная страница просмотра отчета в `admin/report.php`.
- Таблица подозрительных файлов в отчете построена на штатном Bitrix `CAdminList`.
- Контекстное меню подозрительного файла: добавить в whitelist и принудительно поместить в карантин.
- Контекстное меню результатов сканирования: просмотр и удаление.
- Карантин через `Delement\Antivirus\Quarantine\QuarantineManager`.
- Страница управления карантином в `admin/quarantine.php`.
- Белый список через `Delement\Antivirus\Whitelist\WhitelistManager`.
- Действия добавления whitelist-правил из `admin/report.php`.
- Страница управления whitelist в `admin/whitelist.php` на штатном Bitrix `CAdminList`.
- Контекстное меню whitelist-правил: активировать, деактивировать, удалить.
- RU/EN локализация в `lang/ru` и `lang/en`.
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
    report.php
    whitelist.php
    quarantine.php

  lib/
    Admin/
    Config/
    Detection/
    File/
    Quarantine/
    Report/
    Rules/
    Scanner/
    Storage/
    Whitelist/

  lang/
    en/
    ru/

  tests/
    engine_smoke.php
    external_signatures_smoke.php
    scan_profiles_smoke.php
    delete_action_smoke.php
    file_filter_smoke.php
    parallel_scan_lock_smoke.php
    cancelled_report_smoke.php
    quarantine_smoke.php
    report_storage_smoke.php
    session_storage_smoke.php
    whitelist_smoke.php

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

Встроенные правила загружаются через `SignatureLoader::loadDefaultRules()`. Если в настройках указан `signatures_path`, scanner дополнительно загружает файл через `SignatureLoader::loadFromFile()` и объединяет внешние regex-сигнатуры со встроенными правилами. Формат внешнего файла: одна regex-сигнатура на строку, пустые строки и строки с `#` в начале игнорируются.

## Настройки

В `options.php` доступны:

- путь сканирования;
- профиль сканирования Bitrix: `quick`, `standard`, `deep`;
- профиль чувствительности: `balanced`, `strict`, `paranoid`;
- действие: `report`, `quarantine`, `delete`;
- `dry-run`;
- путь карантина;
- путь к внешнему файлу сигнатур;
- размер порции сканирования;
- максимальный размер файла;
- список исключений.

Исключения путей сравниваются как нормализованный path-prefix: путь равен исключению или начинается с `excludePath/`.

Профили сканирования:

- `quick`: проверяет `/upload`, `/bitrix/php_interface`, `/local/php_interface`, `/local/modules`; отсутствующие пути пропускаются;
- `standard`: проверяет выбранный путь целиком с учетом исключений и стандартного набора исполняемых/web-расширений;
- `deep`: проверяет выбранный путь с расширенным набором расширений, включая `.txt`, `.sql`, `.svg`, `.htaccess`, `susp`, `suspected`, `infected`, `vir`.

Для destructive actions рекомендуется сначала запускать `dry-run`. При включенном `dry-run` модуль только фиксирует планируемое действие в отчете и не меняет файловую систему.

## Карантин

При действии `quarantine` и выключенном `dry-run` найденный файл переносится в защищенный каталог карантина. Payload хранится как `payload.bin`, а рядом создается `meta.json` с исходным путем, SHA256, scan id и деталями срабатывания.
Перед и после перемещения проверяется SHA256 checksum. Каталоги карантина закрываются правами `0700`, payload и metadata-файлы правами `0600`.

Страница `/bitrix/admin/delement_antivirus_quarantine.php` позволяет просматривать записи, восстанавливать файл и удалять payload из карантина. Восстановление не перезаписывает существующий файл.
Просмотр карантина доступен с правом модуля `R`, но восстановление и удаление payload требуют пользователя Bitrix admin и права `W` на модуль.
Restore в критичные системные пути, например `.htaccess`, `bitrix/.settings.php`, `bitrix/php_interface/dbconn.php`, `bitrix/modules/*`, требует отдельного подтверждения. Restore/delete пишут события в журнал внутри `meta.json` и отображают последнее событие в таблице карантина.

При действии `delete` и выключенном `dry-run` файл удаляется через тот же защищенный контур: сначала создается metadata-запись и файл переносится во временный quarantine payload, затем payload удаляется. В результате в карантине остается `meta.json` со статусом `deleted`, SHA256, исходным путем, scan id и findings; восстановить содержимое после `delete` нельзя.

## Белый список

Whitelist применяется во время сканирования до выполнения действий `report` или `quarantine`. Если правило исключает все findings файла, результат пересчитывается в `clean`, и файл не попадает в карантин.

Поддерживаются правила:

- точный путь файла;
- regex пути;
- SHA256-хэш файла;
- signature id;
- конкретная пара `file + signature id`.

Правила добавляются из страницы просмотра отчета сканирования. Управление списком доступно в админке: `Сервисы -> Антивирус: поиск вирусов и троянов -> Белый список`. Пользовательские regex валидируются перед сохранением.

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

Повторный `start_scan` при уже активной сессии не запускает второй обход файлов. Endpoint возвращает `scan_already_running` и `active_scan_id`, а активный marker снимается при статусах `finished`, `cancelled` или `failed`.

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

Smoke-test внешних сигнатур:

```bash
php bitrix/modules/delement.antivirus/tests/external_signatures_smoke.php
```

Smoke-test профилей сканирования:

```bash
php bitrix/modules/delement.antivirus/tests/scan_profiles_smoke.php
```

Smoke-test delete action:

```bash
php bitrix/modules/delement.antivirus/tests/delete_action_smoke.php
```

Smoke-test исключений путей:

```bash
php bitrix/modules/delement.antivirus/tests/file_filter_smoke.php
```

Smoke-test защиты от параллельных сканов:

```bash
php bitrix/modules/delement.antivirus/tests/parallel_scan_lock_smoke.php
```

Smoke-test сохранения отчета при отмене:

```bash
php bitrix/modules/delement.antivirus/tests/cancelled_report_smoke.php
```

Smoke-test хранилища отчетов:

```bash
php bitrix/modules/delement.antivirus/tests/report_storage_smoke.php
```

Smoke-test карантина:

```bash
php bitrix/modules/delement.antivirus/tests/quarantine_smoke.php
```

Smoke-test whitelist:

```bash
php bitrix/modules/delement.antivirus/tests/whitelist_smoke.php
```

## Важные ограничения

- Это сигнатурный и rule-based scanner, а не полноценная EDR/AV/WAF-система.
- Автоматическое удаление не должно быть поведением по умолчанию.
- Любые destructive actions должны иметь `dry-run`, проверку прав, `sessid` и явное подтверждение.
- `/upload/` целиком не исключается: PHP-файлы внутри `/upload/` являются важным индикатором компрометации.

## Следующий этап

Ближайшие задачи: фильтры результатов, cron runner и audit log действий карантина.
