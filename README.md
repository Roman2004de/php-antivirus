# delement.antivirus

Модуль 1С-Битрикс **«Антивирус: поиск вирусов и троянов»**.

Текущий репозиторий больше не содержит самостоятельный CLI-сканер. Корневые `antivirus.php` и `signatures.txt` вынесены в отдельный проект, а здесь развивается устанавливаемый модуль для 1С-Битрикс Marketplace.

## Паспорт модуля

- `MODULE_ID`: `delement.antivirus`
- Псевдоним: `antivirus`
- Версия: `0.0.4`
- Партнер: `Цифровой Элемент`
- Сайт партнера: `https://d-element.ru`
- Язык интерфейса: русский и английский
- Минимальная цель совместимости: PHP 7.4+, с обязательной проверкой на актуальной версии PHP, поддерживаемой Bitrix
- Composer-зависимость: `nikic/php-parser:^4.18` для AST-анализа PHP

## Что уже реализовано

- Устанавливаемый skeleton модуля.
- `install/index.php`, `install/version.php`, `include.php`, `options.php`.
- Административные proxy-файлы для `/bitrix/admin`.
- Страницы админки: сканирование, результаты, карантин.
- Настройки через `Bitrix\Main\Config\Option`.
- D7 autoload map для классов модуля.
- Модульный scanner engine в `lib/`.
- Базовые правила детекта: PHP, JavaScript, HTML, Bitrix-specific.
- Быстрый `common_strings` prefilter для regex-правил с настройкой и CLI-флагами.
- `normalized_hash` для текстовых файлов: устойчивый SHA-256 от содержимого без пробелов и переносов строк.
- FindingSuppressor: точечное скрытие конкретного false positive по стабильному finding fingerprint.
- EntropyAnalyzer: эвристическое обнаружение длинных высокоэнтропийных encoded payload с тегами и CLI-флагами.
- UrlExtractor/UrlAnalyzer: извлечение внешних URL, remote loaders, iframe/script-инъекций, `.htaccess` redirects и локальная suspicious-domain база.
- Known Malware Hash Database: быстрая проверка SHA-256 через prefix-index и полную пользовательскую/тестовую базу malware-хешей.
- Panelica Malware Signatures importer: конвертация MIT-licensed Panelica hash signatures во внутренний формат hash DB с сохранением attribution.
- Поддержка внешнего файла regex-сигнатур с добавлением к встроенным правилам.
- AST-анализ PHP поверх regex-слоя: опасные вызовы, динамические вызовы, include/require и encoded execution chains.
- Taint-анализ PHP: request/php://input/filter_input -> переменные/трансформеры -> dangerous sink с сохранением trace.
- Усиленный анализ `.htaccess`: PHP handlers для статических расширений, auto_prepend/append, embedded code, suspicious rewrite, WordPress-маркеры и access bypass.
- Профили сканирования Bitrix: `quick`, `standard`, `deep`.
- AJAX actions: `ping`, `start_scan`, `scan_step`, `get_status`, `cancel_scan`.
- Пошаговое сканирование через AJAX.
- CLI-сканирование через `install/tools/scan.php` с `--help`, `--json`, `dry-run` и корректными exit codes.
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
      Ast/
      Entropy/
      Hash/
      Htaccess/
      Taint/
      Url/
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
    cli_scan_smoke.php

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
- `Delement\Antivirus\Detection\Ast\AstAnalyzer`
- `Delement\Antivirus\Detection\Ast\PhpAstParser`
- `Delement\Antivirus\Detection\Ast\NodeCollector`
- `Delement\Antivirus\Detection\Entropy\EntropyAnalyzer`
- `Delement\Antivirus\Detection\Entropy\EntropyCalculator`
- `Delement\Antivirus\Detection\Hash\KnownMalwareHashAnalyzer`
- `Delement\Antivirus\Detection\Hash\HashDatabase`
- `Delement\Antivirus\Detection\Hash\HashPrefixIndex`
- `Delement\Antivirus\Detection\Hash\Import\PanelicaHashDownloader`
- `Delement\Antivirus\Detection\Hash\Import\PanelicaHashImporter`
- `Delement\Antivirus\Detection\Hash\Import\PanelicaHashNormalizer`
- `Delement\Antivirus\Baseline\BaselineManager`
- `Delement\Antivirus\Baseline\BaselineStorage`
- `Delement\Antivirus\Baseline\BaselineRecord`
- `Delement\Antivirus\Detection\Baseline\BaselineAnalyzer`
- `Delement\Antivirus\Detection\Baseline\BaselineFindingFactory`
- `Delement\Antivirus\Detection\Htaccess\HtaccessAnalyzer`
- `Delement\Antivirus\Detection\Taint\TaintAnalyzer`
- `Delement\Antivirus\Detection\Taint\TaintPropagator`
- `Delement\Antivirus\Detection\Taint\TaintSinkDetector`
- `Delement\Antivirus\Detection\Url\UrlAnalyzer`
- `Delement\Antivirus\Detection\Url\UrlExtractor`
- `Delement\Antivirus\Detection\Url\SuspiciousDomainList`
- `Delement\Antivirus\File\FileCollector`
- `Delement\Antivirus\File\FileFilter`
- `Delement\Antivirus\File\FileReader`

Движок не пишет HTML, не вызывает `echo`/`exit` и возвращает структурированные результаты, чтобы его можно было использовать из админки, AJAX, cron runner и будущего CLI-wrapper модуля.

Встроенные правила загружаются через `SignatureLoader::loadDefaultRules()`. Если в настройках указан `signatures_path`, scanner дополнительно загружает файл через `SignatureLoader::loadFromFile()` и объединяет внешние regex-сигнатуры со встроенными правилами. Формат внешнего файла: одна regex-сигнатура на строку, пустые строки и строки с `#` в начале игнорируются.

Для PHP-файлов дополнительно включается AST-слой на базе `nikic/php-parser`. Он применяется только к расширениям `.php`, `.php5`, `.php7`, `.phtml`, `.module`, `.include` и только в пределах настройки `ast_max_file_size`. При отсутствии Composer-зависимости AST-слой не останавливает сканирование, но regex-правила продолжают работать.

Taint-слой работает внутри AST-прохода и ищет цепочки от пользовательских источников (`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES`, `$_SERVER` кроме `DOCUMENT_ROOT`, `php://input`, `filter_input`) к опасным sink-вызовам (`eval`, `assert`, shell-команды, include/require, file write, `curl_setopt(CURLOPT_URL)`, `mail`, callback-вызовы). Findings категории `php_taint` содержат поле `trace` с source, transforms, sink и расчетом риска.

Файлы `.htaccess` анализируются отдельным слоем `HtaccessAnalyzer`. Он ищет попытки включить PHP-исполнение для статических расширений, `auto_prepend_file`/`auto_append_file`, PHP/JS-код внутри `.htaccess`, подозрительные rewrite-правила, WordPress-маркеры внутри Bitrix-проекта и директивы обхода доступа в чувствительных каталогах.

Entropy-слой ищет длинные строки с высокой Shannon entropy: base64/hex payload и packed JS/PHP. В стандартном профиле он выключен по умолчанию, в deep-профиле может включаться автоматически через настройку `enable_entropy_in_deep_profile`, а в CLI управляется флагами `--enable-entropy` и `--disable-entropy`. Findings категории `entropy` содержат `confidence`, `entropy`, `length` и теги `engine:entropy`, `risk:entropy`, `risk:encoded_payload`.

URL-слой извлекает внешние `http://` и `https://` URL из PHP, JavaScript, HTML и `.htaccess`. Он отдельно помечает remote payload loaders, `iframe src`, `script src`, `document.write('<script ...>')`, `.htaccess` redirects и совпадения с локальной JSON-базой подозрительных доменов. Findings категории `url` содержат `url`, `domain`, `trace` и теги `engine:url`, `risk:external_url`, а для loader-сценариев также `risk:remote_loader`. Обычный внешний URL фиксируется как informational finding со score `0` и не увеличивает `found_files`; такие срабатывания считаются отдельно в `informational_findings_total`. База доменов находится в `var/signatures/suspicious_domains.json` и не содержит сторонних malware databases.

Hash DB слой считает SHA-256 файла, проверяет первые 8-12 символов по prefix-index и только после этого сверяет полный хеш. Prefix-only match не создает malware finding. Полное совпадение дает `known_malware_hash_match` с `severity=critical`, `score=100`, `confidence=high`, `recommendation=quarantine`, тегами `engine:hash_db` и `risk:known_malware_hash`. Базы `var/signatures/malware_hashes.json` и `var/signatures/malware_hash_prefixes.json` являются внутренним runtime-форматом; scanner не зависит от структуры внешних репозиториев.

## Baseline / Integrity Scanner

Baseline scanner хранит пользовательский снимок целостности файлов сайта и сравнивает текущие файлы с этим снимком. Это не `CoreIntegrityChecker` Bitrix: модуль не сверяет файлы с эталоном ядра Bitrix, а сравнивает сайт с ранее созданным пользовательским baseline.

Snapshot хранится через защищенный runtime storage модуля и содержит путь файла, размер, `mtime`, SHA-256 и `normalized_hash`, если normalized hash включен в настройках. Проверка baseline выявляет:

- новые файлы;
- измененные файлы;
- удаленные файлы;
- изменения в критичных директориях Bitrix;
- PHP-файлы в `/upload`;
- новые файлы в `/bitrix/tools` и `/bitrix/admin`.

Findings категории `baseline` получают теги `engine:baseline` и `risk:baseline_change`. Для PHP-файлов в `/upload` дополнительно добавляются `path:upload` и `risk:executable_upload`.

CLI:

```bash
php /home/site/public_html/bitrix/tools/delement.antivirus/scan.php \
  --baseline-create \
  --path=/home/site/public_html

php /home/site/public_html/bitrix/tools/delement.antivirus/scan.php \
  --baseline-check \
  --path=/home/site/public_html \
  --json

php /home/site/public_html/bitrix/tools/delement.antivirus/scan.php \
  --baseline-update \
  --path=/home/site/public_html \
  --force
```

В Web UI раздел доступен как `Сервисы -> Антивирус: поиск вирусов и троянов -> Целостность / Baseline`. Там можно создать baseline, проверить сайт, обновить baseline и скачать последний baseline report в JSON.

## Panelica Malware Signatures Integration

Модуль умеет импортировать SHA-256 hash signatures из [Panelica Malware Signatures](https://github.com/Panelica/malware-signatures). Panelica Malware Signatures распространяется под MIT License. `delement.antivirus` не копирует код Panelica и не использует YARA/regex patterns на этапе hash DB; importer читает только `json/hashes.json` или `hashes/sha256.txt`, преобразует их во внутренний формат и сохраняет attribution.

База Panelica не зашивается в модуль и не скачивается автоматически при установке. Импорт выполняется только по явному действию администратора: из локальной копии или через отдельный download/import режим.

При импорте создаются или обновляются:

- `var/signatures/malware_hashes.json`;
- `var/signatures/malware_hash_prefixes.json`;
- `var/signatures/sources/panelica/LICENSE`;
- `var/signatures/sources/panelica/README.source.md`;
- `var/signatures/sources/panelica/import_metadata.json`.
- `var/signatures/sources/panelica/downloads/...` при download/import режиме.

CLI-импорт из локальной копии:

```bash
git clone https://github.com/Panelica/malware-signatures.git /tmp/panelica-malware-signatures

php /home/site/public_html/bitrix/tools/delement.antivirus/scan.php \
  --import-panelica-hashes=/tmp/panelica-malware-signatures \
  --json
```

CLI download/import из allowlisted Panelica URL:

```bash
php /home/site/public_html/bitrix/tools/delement.antivirus/scan.php \
  --download-panelica-hashes \
  --json
```

По умолчанию используется источник `https://github.com/Panelica/malware-signatures`. Downloader получает только `LICENSE`, `json/hashes.json` и `hashes/sha256.txt`, складывает их в локальный каталог `var/signatures/sources/panelica/downloads/...`, затем запускает обычный importer. Разрешены только URL Panelica на `github.com`/`raw.githubusercontent.com`; произвольные внешние URL из Web UI не принимаются.

Дополнительные параметры импорта:

- `--panelica-hashes-json=PATH`: явно указать `json/hashes.json`;
- `--panelica-sha256-txt=PATH`: явно указать `hashes/sha256.txt`;
- `--panelica-license=PATH`: явно указать `LICENSE`;
- `--download-panelica-hashes`: скачать Panelica hash sources из allowlisted URL и импортировать;
- `--panelica-download-url=URL`: переопределить URL источника Panelica для CLI;
- `--malware-hashes-output=PATH`: путь итогового `malware_hashes.json`;
- `--malware-prefixes-output=PATH`: путь итогового `malware_hash_prefixes.json`;
- `--malware-hash-prefix-length=N`: длина prefix-index от 8 до 12;
- `--panelica-source-commit=HASH`: commit/version источника для metadata.

В Web UI импорт доступен в настройках модуля в блоке `Known malware -> Panelica Malware Signatures`: можно указать локальный путь к уже скачанному репозиторию и нажать `Import from local path`, либо нажать `Download and import`. Перед download/import показываются источник `https://github.com/Panelica/malware-signatures`, лицензия MIT и пояснение, что будут импортированы SHA-256-хеши во внутренний формат. Никакой автоматической загрузки при установке нет.

Attribution: This product can import hash signatures from Panelica Malware Signatures. Panelica Malware Signatures is distributed under the MIT License. Source: https://github.com/Panelica/malware-signatures

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
- `common_strings` prefilter;
- normalized hash;
- включение AST-анализа PHP;
- максимальный размер PHP-файла для AST-анализа;
- entropy analyzer;
- минимальная длина строки и порог entropy;
- URL analyzer;
- путь к локальной базе подозрительных доменов;
- Known malware hash database;
- путь к полной базе malware-хешей и prefix-index;
- длина prefix-index для импорта malware-хешей;
- локальный путь Panelica, download source URL, last import date, imported hashes count, source license и source commit/version;
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

## CLI-сканирование

CLI entrypoint устанавливается в:

```text
/bitrix/tools/delement.antivirus/scan.php
```

Пример запуска:

```bash
php /home/site/public_html/bitrix/tools/delement.antivirus/scan.php --path=/home/site/public_html --scan-profile=deep --profile=strict --action=report --dry-run --json
```

Основные параметры:

- `--path=PATH`: путь сканирования внутри `DOCUMENT_ROOT`;
- `--document-root=PATH`: корневая директория сайта, если ее нужно указать явно;
- `--scan-profile=quick|standard|deep`: профиль обхода файлов;
- `--profile=balanced|strict|paranoid`: профиль чувствительности;
- `--action=report|quarantine|delete`: действие для подозрительных файлов;
- `--dry-run`: не менять файловую систему, только показать планируемые действия;
- `--no-dry-run`: разрешить реальные изменения для `quarantine` или `delete`;
- `--force`: обязательный флаг для `quarantine`/`delete` вместе с `--no-dry-run`;
- `--json`: вывести итоговый JSON в `STDOUT`;
- `--signatures=PATH`: подключить внешний файл regex-сигнатур;
- `--report=PATH`: сохранить копию итогового JSON-отчета в заданный файл;
- `--enable-ast`: включить PHP AST-анализ;
- `--disable-ast`: выключить PHP AST-анализ;
- `--enable-prefilter`: включить быстрый `common_strings` prefilter для regex-правил;
- `--disable-prefilter`: выключить быстрый `common_strings` prefilter для regex-правил;
- `--enable-normalized-hash`: включить расчет `normalized_hash`;
- `--disable-normalized-hash`: выключить расчет `normalized_hash`;
- `--normalized-hash-max-file-size-mb=N`: максимальный размер файла для `normalized_hash` от 1 до 1024 МБ;
- `--enable-entropy`: включить entropy analyzer;
- `--disable-entropy`: выключить entropy analyzer, включая auto-enable для deep/strict;
- `--entropy-threshold=N`: порог Shannon entropy от 0.1 до 8.0;
- `--entropy-min-length=N`: минимальная длина строки-кандидата от 20 до 100000;
- `--enable-url-analyzer`: включить анализ внешних URL;
- `--disable-url-analyzer`: выключить анализ внешних URL;
- `--suspicious-domains=PATH`: путь к пользовательской/тестовой JSON-базе подозрительных доменов;
- `--enable-hash-db`: включить базу известных malware-хешей;
- `--disable-hash-db`: выключить базу известных malware-хешей;
- `--malware-hashes=PATH`: путь к JSON-файлу полных SHA-256 malware-хешей;
- `--malware-hash-prefixes=PATH`: путь к JSON-файлу SHA-256 prefix-index;
- `--import-panelica-hashes=PATH`: импортировать Panelica Malware Signatures hashes из локального репозитория;
- `--download-panelica-hashes`: скачать Panelica hash sources из allowlisted URL и импортировать;
- `--panelica-download-url=URL`: переопределить URL источника Panelica для CLI;
- `--panelica-hashes-json=PATH`: явно указать Panelica `json/hashes.json`;
- `--panelica-sha256-txt=PATH`: явно указать Panelica `hashes/sha256.txt`;
- `--panelica-license=PATH`: явно указать Panelica `LICENSE`;
- `--malware-hashes-output=PATH`: путь выходного файла полных malware-хешей;
- `--malware-prefixes-output=PATH`: путь выходного файла prefix-index;
- `--malware-hash-prefix-length=N`: длина prefix-index от 8 до 12;
- `--panelica-source-commit=HASH`: commit/version источника для attribution metadata;
- `--baseline-create`: создать пользовательский baseline для `--path`;
- `--baseline-check`: сравнить `--path` с сохраненным baseline;
- `--baseline-update`: перезаписать baseline новым снимком, требует `--force`;
- `--ast-max-file-size=N`: лимит размера PHP-файла для AST-анализа в байтах;
- `--exclude=PATH`: добавить исключение, можно указывать несколько раз;
- `--batch-size=N`: размер порции сканирования от 1 до 1000;
- `--max-file-size-mb=N`: максимальный размер файла от 1 до 1024 МБ;
- `--quarantine-path=PATH`: путь карантина;
- `--help`: вывести справку без запуска сканирования;
- `--version`: вывести версию модуля из `install/version.php`.

По умолчанию CLI использует настройки модуля из Bitrix Option, а переданные аргументы переопределяют их только для текущего запуска. `dry-run` остается безопасным режимом по умолчанию. Для реального карантина или удаления нужно явно указать `--no-dry-run --force`.

Exit codes:

- `0`: сканирование завершено, подозрительные файлы не найдены;
- `1`: сканирование завершено, есть подозрительные файлы;
- `2`: ошибка аргументов или конфигурации;
- `3`: runtime-ошибка во время сканирования;
- `4`: уже запущено другое сканирование.

При `--json` в `STDOUT` выводится только итоговый machine-readable JSON. Полный отчет сохраняется через `ReportManager`, путь к нему возвращается в поле `report_path`. Если указан `--report=PATH`, CLI дополнительно сохраняет копию отчета в этот файл, `report_path` указывает на него, а исходный runtime-путь возвращается в `runtime_report_path`.

## Сборка релиза

Windows release-скрипт находится в корне проекта:

```cmd
release.cmd --version=0.0.4
```

Скрипт создает архив `0.0.4.zip` в корне репозитория. Внутри архива находится папка `0.0.4`, содержащая файлы модуля из `bitrix/modules/delement.antivirus`. В staging-копии перед упаковкой обновляется `install/version.php` под переданную версию; исходные файлы проекта не изменяются.

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

Smoke-test AST-анализа PHP:

```bash
php bitrix/modules/delement.antivirus/tests/ast_analysis_smoke.php
```

Smoke-test taint-анализа PHP:

```bash
php bitrix/modules/delement.antivirus/tests/taint_analysis_smoke.php
```

Smoke-test `.htaccess`-анализа:

```bash
php bitrix/modules/delement.antivirus/tests/htaccess_analysis_smoke.php
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

Smoke-test CLI-режима:

```bash
php bitrix/modules/delement.antivirus/tests/cli_scan_smoke.php
```

Smoke-test normalized hash:

```bash
php bitrix/modules/delement.antivirus/tests/normalized_hash_smoke.php
```

Smoke-test FindingSuppressor:

```bash
php bitrix/modules/delement.antivirus/tests/finding_suppressor_smoke.php
```

Smoke-test EntropyAnalyzer:

```bash
php bitrix/modules/delement.antivirus/tests/entropy_analyzer_smoke.php
```

Smoke-test UrlExtractor:

```bash
php bitrix/modules/delement.antivirus/tests/url_extractor_smoke.php
```

Smoke-test Known Malware Hash Database:

```bash
php bitrix/modules/delement.antivirus/tests/hash_database_smoke.php
```

Smoke-test Panelica hash import:

```bash
php bitrix/modules/delement.antivirus/tests/panelica_hash_import_smoke.php
php bitrix/modules/delement.antivirus/tests/panelica_hash_download_smoke.php
php bitrix/modules/delement.antivirus/tests/hash_database_panelica_smoke.php
```

Smoke-test Baseline / Integrity Scanner:

```bash
php bitrix/modules/delement.antivirus/tests/baseline_smoke.php
php bitrix/modules/delement.antivirus/tests/baseline_critical_paths_smoke.php
```

## Важные ограничения

- Это сигнатурный и rule-based scanner, а не полноценная EDR/AV/WAF-система.
- Автоматическое удаление не должно быть поведением по умолчанию.
- Любые destructive actions должны иметь `dry-run`, проверку прав, `sessid` и явное подтверждение.
- `/upload/` целиком не исключается: PHP-файлы внутри `/upload/` являются важным индикатором компрометации.

## Следующий этап

Этап 10.8: WebShell Fingerprints на собственных эвристиках без сторонних fingerprint-баз.
