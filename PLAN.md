# План разработки delement.antivirus

Модуль 1С-Битрикс Marketplace **«Антивирус: поиск вирусов и троянов»**.

## Цель

Создать production-oriented модуль для 1С-Битрикс, который позволяет администратору:

- запускать проверку файлов сайта из административной панели;
- видеть прогресс сканирования;
- получать список подозрительных файлов;
- понимать причины срабатывания;
- безопасно помещать файлы в карантин;
- запускать проверку по cron;
- использовать dry-run перед destructive actions;
- настраивать исключения;
- подключать внешний файл сигнатур;
- использовать профили сканирования Bitrix;
- использовать профили чувствительности;
- получать JSON-отчеты для аудита и автоматизации.

## Принцип продукта

Безопасный порядок действий:

```text
scan -> explain -> review -> quarantine -> restore/delete manually
```

Автоматическое удаление без ручного подтверждения не должно быть поведением по умолчанию.

## Паспорт

- `MODULE_ID`: `delement.antivirus`
- Псевдоним: `antivirus`
- Версия: `0.0.4`
- Партнер: `Цифровой Элемент`
- URI партнера: `https://d-element.ru`
- Namespace: `Delement\Antivirus`
- Composer: используется для `nikic/php-parser:^4.18`
- Интерфейс: русский и английский

## Текущий статус

Стадия: MVP с работающим сканированием, отчетами, карантином, CLI runner, AST-анализом PHP, taint-анализом request-to-sink, усиленным `.htaccess`-анализом и `common_strings` prefilter для regex pipeline.

Уже есть устанавливаемый skeleton, настройки, модульный scanner engine, AJAX-пошаговое сканирование, results storage/UI, RU/EN локализация и базовый карантин с восстановлением.
Scanner использует встроенные правила и может добавлять к ним внешний файл regex-сигнатур из настройки `signatures_path`.
Добавлены профили сканирования Bitrix `quick`, `standard`, `deep`.
Поверх regex-правил добавлен AST-анализ PHP через `nikic/php-parser`.
Внутри AST-прохода добавлен taint-анализ цепочек от request/php://input/filter_input к dangerous sink.
Файлы `.htaccess` анализируются отдельным конфигурационным analyzer-слоем.

## Этапы

### [x] Этап 1. Installable skeleton

Цель: создать устанавливаемый модуль.

Сделано:

- создана структура `bitrix/modules/delement.antivirus`;
- добавлены `install/index.php`, `install/version.php`;
- добавлены `include.php`, `default_option.php`, `options.php`;
- добавлены admin proxy files;
- добавлены страницы `scan.php`, `results.php`, `quarantine.php`;
- добавлен `admin/menu.php`;
- реализованы `DoInstall()` и `DoUninstall()`;
- добавлены `lang/ru` файлы;
- добавлены `install/js`, `install/css`, `install/tools`;
- каталог `var/` закрыт от веб-доступа.

Acceptance:

- [x] модуль имеет стандартную структуру;
- [x] модуль регистрируется через `RegisterModule`;
- [x] proxy-файлы копируются в `/bitrix/admin`;
- [x] uninstall удаляет proxy/assets/tools;
- [ ] установка/удаление проверены на живом Bitrix-стенде.

### [x] Этап 2. Settings UI

Цель: сделать настройки модуля через Bitrix UI.

Сделано:

- форма настроек в `options.php`;
- хранение через `Bitrix\Main\Config\Option`;
- поля: scan path, scan profile, profile, action, dry-run, quarantine path, exclusions, batch size, max file size;
- добавлена настройка `signatures_path` для внешнего файла regex-сигнатур;
- добавлены настройки `enable_ast_analysis` и `ast_max_file_size`;
- добавлена настройка `scan_profile`: `quick`, `standard`, `deep`;
- дефолты в `default_option.php`;
- проверка `sessid`;
- базовая валидация путей, диапазонов и действия;
- исключения путей сравниваются как нормализованный path-prefix, без substring false positives;
- предупреждение для опасных действий `quarantine` и `delete`.

Acceptance:

- [x] настройки сохраняются;
- [x] настройки загружаются;
- [x] значения валидируются;
- [x] внешний файл сигнатур валидируется на существование и доступность для чтения;
- [x] AST-анализ можно включить/выключить и ограничить по размеру PHP-файла;
- [x] исключения путей не дают ложных совпадений по середине строки;
- [x] можно сбросить настройки к значениям по умолчанию;
- [ ] форма проверена на живом Bitrix-стенде.

### [x] Этап 3. Scanner engine extraction

Цель: вынести scanner engine в reusable-классы модуля.

Сделано:

- создан `Delement\Antivirus\Config\ScanConfig`;
- создан `Delement\Antivirus\Scanner\Scanner`;
- создан файловый слой `FileCollector`, `FileFilter`, `FileReader`, `FileTypeDetector`;
- `ScanConfig` вычисляет профильные пути и набор расширений для `quick`, `standard`, `deep`;
- `FileCollector` умеет собирать файлы по набору путей из `ScanConfig`;
- создан detection слой `Detector`, `RuleEngine`, `SignatureLoader`;
- создан AST detection слой `Detection/Ast`: parser wrapper, context collector и детекторы dangerous/dynamic/encoded chains;
- создан `.htaccess` detection слой `Detection/Htaccess`: analyzer, rule DTO и finding factory;
- создан taint detection слой `Detection/Taint`: source detector, propagator, sink detector, trace и finding factory;
- созданы DTO `ScanResult`, `ScanSummary`, `Finding`;
- `Finding` поддерживает необязательное поле `trace` для taint-срабатываний;
- добавлены `Severity` и `Verdict`;
- добавлены правила в `lib/Rules`: PHP, JavaScript, HTML, Bitrix-specific;
- `Scanner` объединяет встроенные правила с внешними сигнатурами из `ScanConfig::getSignaturesPath()`;
- `Detector` выполняет AST-анализ PHP поверх regex-анализа для `.php`, `.php5`, `.php7`, `.phtml`, `.module`, `.include`;
- `Detector` выполняет отдельный `.htaccess`-анализ для файлов с basename `.htaccess`;
- `AstAnalyzer` выполняет taint-анализ request -> dangerous sink в том же AST-проходе;
- `Scanner` использует профильные пути через `FileCollector::collectFromConfig()`;
- scanner не зависит от UI;
- scanner не вызывает `echo` и `exit`;
- добавлен `tests/engine_smoke.php`.
- добавлен `tests/external_signatures_smoke.php`.
- добавлен `tests/scan_profiles_smoke.php`.
- добавлен `tests/ast_analysis_smoke.php`.
- добавлен `tests/htaccess_analysis_smoke.php`.
- добавлен `tests/taint_analysis_smoke.php`.

Acceptance:

- [x] scanner работает без UI;
- [x] scanner возвращает структурированный результат;
- [x] scanner не пишет HTML;
- [x] smoke-test находит PHP-файл внутри `/upload/`;
- [x] smoke-test подтверждает срабатывание внешней сигнатуры;
- [x] smoke-test подтверждает поведение профилей `quick`, `standard`, `deep`;
- [x] smoke-test подтверждает AST-срабатывания для `eval`, `system`, dynamic call, encoded chain и `include` из request;
- [x] smoke-test подтверждает `.htaccess` правила: PHP handler для `.jpg`, auto_prepend, embedded code, suspicious rewrite, foreign CMS marker и access bypass;
- [x] smoke-test подтверждает taint-цепочки `eval($_GET)`, `$_POST -> shell_exec`, `$_REQUEST -> include`, dynamic callable, `php://input -> file_put_contents`, `filter_input -> curl_setopt(CURLOPT_URL)`;
- [ ] нужен набор unit/integration tests для правил и false positives.

### [x] Этап 4. AJAX scan

Цель: сделать порционное сканирование из админки.

Сделано:

- `admin/ajax.php` подключает модуль и передает запросы в controller;
- создан `Delement\Antivirus\Admin\AjaxController`;
- создан `Delement\Antivirus\Scanner\ScanSessionStore`;
- реализованы actions: `ping`, `start_scan`, `scan_step`, `get_status`, `cancel_scan`;
- `start_scan` валидирует и собирает несколько путей для quick-профиля;
- `delete` action выполняется через quarantine-like metadata и dry-run protection;
- добавлена защита от параллельных сканов через active session marker и `flock`;
- scan sessions сохраняются в writable runtime-каталог `/bitrix/tmp/delement.antivirus/sessions`;
- JSON reports сохраняются в writable runtime-каталог `/bitrix/tmp/delement.antivirus/reports`;
- отмененное сканирование сохраняет частичный JSON report со статусом `cancelled`;
- UI страницы сканирования показывает прогресс, статус, счетчики и текущий файл;
- JS крутит `scan_step` до `finished` или `cancelled`.
- добавлен `tests/parallel_scan_lock_smoke.php`.

Acceptance:

- [x] endpoint проверяет авторизацию, права и `sessid`;
- [x] scan выполняется порциями;
- [x] есть cancel;
- [x] есть JSON report;
- [x] `delete` не выполняется при включенном `dry-run`;
- [x] повторный `start_scan` не запускает второй параллельный scan;
- [x] при cancel сохраняется частичный report;
- [ ] сценарий проверен в браузере на живом Bitrix-стенде;
- [ ] нужно добавить обработку больших объемов результатов без раздувания session JSON.

### [ ] Этап 5. Results storage и Results UI

Цель: показать результаты сканирования в админке.

Сделано:

- создан `Delement\Antivirus\Report\ReportManager`;
- создан `Delement\Antivirus\Report\JsonReportWriter`;
- сохранение report вынесено из `ScanSessionStore`;
- report получил версионированный JSON-формат: `format`, `format_version`, `summary`, `config`, `results`;
- добавлен список последних отчетов в `admin/results.php`;
- добавлена отдельная страница просмотра деталей отчета `admin/report.php`;
- добавлен экспорт JSON;
- список отчетов переведен на штатный Bitrix `CAdminList`;
- добавлено контекстное меню строки: `Просмотреть`, `Удалить`;
- добавлено удаление результатов сканирования с проверкой прав `W` и `sessid`;
- таблица подозрительных файлов в `admin/report.php` переведена на штатный Bitrix `CAdminList`;
- в контекстное меню подозрительного файла добавлены whitelist-действия;
- добавлено принудительное помещение файла в карантин из контекстного меню отчета;
- отмененные/прерванные сканирования отображаются в списке результатов;
- добавлен `tests/report_storage_smoke.php`.

Задачи:

- добавить фильтры по status, severity, category, signature;
- добавить просмотр деталей finding;
- экранировать excerpts и пути;
- подготовить переход из scan page на results page.

Acceptance:

- [x] результаты сохраняются в writable runtime-каталог;
- [x] список отчетов доступен в админке;
- [x] отчет открывается по `scan_id`;
- [x] экспорт JSON доступен;
- [x] видно file, score, severity, category, signature, excerpt;
- [x] частичные отчеты после cancel доступны в списке;
- [x] подозрительный файл можно отправить в карантин из отчета вручную;
- [ ] можно фильтровать malicious/suspicious;
- [ ] большие фрагменты файлов не выводятся без escaping.

### [x] Этап 6. Quarantine

Цель: сделать безопасный карантин.

Сделано:

- создан `Delement\Antivirus\Quarantine\QuarantineManager`;
- реализован quarantine action при AJAX-сканировании;
- файлы переносятся в защищенное хранилище как `payload.bin`;
- рядом сохраняется `meta.json`;
- сохраняются SHA256, исходный путь, scan id, verdict, score, severity и findings;
- checksum проверяется до и после перемещения файла;
- директории карантина закрываются правами `0700`, payload и metadata правами `0600`;
- restore не перезаписывает существующий файл;
- restore в критичные системные пути требует отдельного подтверждения;
- поддержан restore;
- поддержано удаление payload из карантина;
- restore/delete пишут события в журнал metadata;
- добавлен рабочий `admin/quarantine.php`;
- destructive actions требуют права `W`, POST, `sessid` и подтверждение для удаления;
- restore/delete в карантине требуют пользователя Bitrix admin и права `W` на модуль;
- `dry-run` не меняет файловую систему и сохраняет только планируемое действие;
- `delete` сначала создает metadata-запись и quarantine payload, затем удаляет payload, оставляя audit metadata;
- добавлен `tests/quarantine_smoke.php`.
- добавлен `tests/delete_action_smoke.php`.

Осталось улучшить:

- добавить отдельный audit log действий restore/delete;
- добавить переходы между отчетом и записью карантина;
- добавить фильтры/поиск по карантину.

Acceptance:

- [x] файлы не перезаписываются;
- [x] metadata создается;
- [x] checksum до/после перемещения проверяется;
- [x] restore работает;
- [x] restore критичных системных файлов блокируется без подтверждения;
- [x] restore/delete пишут журнал событий;
- [x] dry-run не меняет файловую систему;
- [x] delete action оставляет metadata со статусом `deleted`;
- [x] restore/delete payload из карантина доступны только Bitrix admin с правом `W`;
- [x] destructive actions требуют права уровня `W`, `sessid` и подтверждение удаления.

### [x] Этап 7. Whitelist

Цель: снизить false positives.

Сделано:

- создан `Delement\Antivirus\Whitelist\WhitelistManager`;
- правила сохраняются в runtime-каталог `/bitrix/tmp/delement.antivirus/whitelist`;
- реализован whitelist по path;
- реализован whitelist по regex path;
- реализован whitelist по hash;
- реализован whitelist по signature id;
- реализовано исключение `file + signature id`;
- whitelist применяется во время AJAX-сканирования до quarantine/report action;
- findings пересчитываются после применения правил: score, severity, verdict;
- из `admin/report.php` можно добавить правило по файлу, хэшу, сигнатуре, `file + signature`;
- из `admin/report.php` можно добавить regex пути;
- добавлена страница управления `admin/whitelist.php` на штатном Bitrix `CAdminList`;
- добавлен пункт меню `Белый список`;
- правила можно просматривать, активировать, деактивировать и удалять через проверку прав + `sessid`;
- пользовательские regex валидируются перед сохранением;
- добавлен `tests/whitelist_smoke.php`.

Осталось улучшить:

- добавить комментарии к правилам из UI;
- показывать whitelisted findings в отчетах отдельным блоком.

Acceptance:

- [x] файл можно добавить в whitelist;
- [x] конкретную сигнатуру можно исключить для файла;
- [x] whitelist учитывается при scan;
- [x] пользовательские regex валидируются перед сохранением.

### [x] Этап 8. CLI scan runner

Цель: заменить заглушку `install/tools/scan.php` на реальный CLI-режим сканирования, пригодный для ручного запуска и cron.

Пример целевого запуска:

```bash
php scan.php --path=/home/site/public_html --scan-profile=deep --profile=strict --action=report --dry-run --json
```

Задачи:

Сделано:

- UI не изменялся: `admin/*`, `options.php`, JS/CSS админки не трогались;
- `install/tools/scan.php` заменен на тонкий CLI entrypoint;
- entrypoint подключает Bitrix prolog и модуль через штатный bootstrap;
- добавлен backend-only CLI слой: `lib/Cli/ArgvParser.php`, `lib/Cli/ScanCommand.php`;
- добавлен общий backend runner: `lib/Scanner/ScanRunService.php`;
- action-логика вынесена в `lib/Scanner/ScanActionApplier.php`;
- CLI поддерживает args: `--path`, `--scan-profile`, `--profile`, `--action`, `--dry-run`, `--no-dry-run`, `--json`, `--help`, `--version`;
- CLI поддерживает дополнительные args: `--document-root`, `--signatures`, `--report`, `--exclude`, `--batch-size`, `--max-file-size-mb`, `--enable-ast`, `--disable-ast`, `--ast-max-file-size`, `--force`, `--quarantine-path`;
- реализован режим `--help` с параметрами, примером и exit codes;
- реализован режим `--version`, который берет версию из `install/version.php`;
- scanner engine запускается через общий service-слой;
- whitelist применяется до выполнения action;
- поддержаны действия `report`, `quarantine`, `delete`;
- `dry-run` остается безопасным режимом по умолчанию;
- `--force` обязателен для `quarantine` и `delete` при выключенном `dry-run`;
- защита от параллельных сканов использует active session/lock;
- JSON report сохраняется через `ReportManager`;
- `--report=/path/report.json` сохраняет копию итогового JSON-отчета в заданный путь для cron/CI/CD/DevOps;
- при `--json` возвращается machine-readable JSON;
- наружу не выводятся stack trace, file/line и debug-информация;
- реализованы exit codes `0`, `1`, `2`, `3`, `4`;
- описание CLI-режима добавлено в `README.md`;
- добавлен `tests/cli_scan_smoke.php`.

Acceptance:

- [x] scan запускается из CLI command layer;
- [x] `--help` выводит справку без запуска сканирования;
- [x] `--version` выводит версию из `install/version.php`;
- [x] CLI поддерживает целевой пример запуска;
- [x] report сохраняется;
- [x] report можно экспортировать в заданный CLI-путь через `--report`;
- [x] whitelist применяется;
- [x] `quarantine` и `delete` защищены `dry-run` и `--force`;
- [x] параллельный CLI/AJAX scan не стартует вторую активную сессию;
- [x] exit code корректный;
- [x] вывод JSON не ломается логами.
- [x] README содержит описание CLI-режима и примеры использования.

### [ ] Этап 9. Marketplace polish

Цель: подготовить модуль к ручной проверке перед публикацией.

Задачи:

- вынести все тексты в `lang/ru` и `lang/en`;
- убрать debug output;
- проверить install/uninstall;
- проверить права;
- проверить `sessid`;
- проверить path validation;
- подготовить README;
- подготовить changelog;
- подготовить screenshots;
- проверить совместимость с актуальными требованиями 1С-Битрикс Marketplace.

Acceptance:

- [ ] модуль ставится и удаляется без ошибок;
- [ ] нет debug output;
- [ ] нет hardcoded абсолютных путей;
- [ ] административные страницы проверяют права;
- [ ] AJAX проверяет `sessid`;
- [ ] uninstall корректно удаляет proxy-файлы;
- [ ] документация готова.

## Новый этап расширения detector platform

Цель новых работ: расширить модуль `delement.antivirus` комплексным набором подсистем, усиливающих качество обнаружения вредоносного кода, производительность regex-детектора, устойчивость поиска к обфускации, контроль целостности файлов, Bitrix-aware анализ сущностей из базы данных, отчетность, фильтрацию и управление false positive.

Новые функции должны быть доступны:

- в веб-интерфейсе модуля;
- в CLI-режиме;
- в JSON-отчетах;
- в smoke-тестах.

Все новые функции должны быть отключаемыми через настройки и/или CLI-флаги.

### Требования по уникальности реализации

При реализации запрещено:

- копировать код Bitrix Security;
- копировать код Wordfence или других WordPress-модулей;
- копировать базы сигнатур, malware hash database, regex, CRC, fingerprints;
- копировать внутренние коды срабатываний, тексты сообщений, scoring-массивы и структуру классов сторонних решений.

Разрешено использовать `/reference` только как reference-only источник:

- идею проверки;
- тип проверяемой сущности;
- общий сценарий обнаружения;
- архитектурный подход;
- категории риска.

Для Bitrix Security reference-only можно смотреть:

- `security/classes/general/xscan.php`;
- `security/classes/general/xscan_htaccess.php`;
- `security/admin/xscan_htaccess.php`;
- `security/admin/security_file_verifier.php`.

Для WordPress/Wordfence-подобных решений можно использовать только идеи:

- common strings prefilter;
- normalized hash;
- entropy analysis;
- URL extraction;
- baseline integrity;
- known malware hash lookup.

Нельзя напрямую переносить базы, регулярные выражения, fingerprints или тексты сигнатур.

### Строгий порядок внедрения

Работы внедряются строго поэтапно:

1. Теги результата.
2. `common_strings` prefilter.
3. `normalized_hash`.
4. `FindingSuppressor`.
5. `EntropyAnalyzer`.
6. `UrlExtractor`.
7. Known Malware Hash Database.
8. WebShell Fingerprints.
9. Baseline / Integrity Scanner.
10. `AgentScanner`.
11. `EventHandlerScanner`.
12. `TemplateConditionScanner`.
13. `DbTriggerScanner`.
14. `CoreIntegrityChecker` Bitrix.

Причина такого порядка:

- Tags нужны почти всем последующим подсистемам;
- `common_strings` prefilter ускоряет базовый regex pipeline;
- `normalized_hash` нужен для отчетов, baseline и будущих сравнений;
- `FindingSuppressor` должен работать со всеми будущими findings;
- entropy, URL, hash DB и fingerprints усиливают file-based detection;
- baseline должен использовать уже готовые hash/normalized_hash;
- Bitrix DB scanners используют существующие `RuleEngine`, AST, Taint, tags и suppress;
- `CoreIntegrityChecker` Bitrix логически отделяется от пользовательского baseline.

### Детализация этапов расширения

#### [x] Этап 10.1. Теги результата

Цель: добавить единый слой тегов для файлов, findings и отчетов.

Сделано:

- расширить `Finding` и JSON report полем `tags`;
- добавить tags в scanner result summary;
- вывести теги в UI результатов и отчета;
- добавить фильтр по тегам;
- добавить CLI/JSON совместимость;
- покрыть smoke-тестом.

#### [x] Этап 10.2. `common_strings` prefilter

Цель: ускорить regex pipeline за счет быстрого предварительного отбора правил.

Сделано:

- добавлен собственный prefilter-слой в `RuleEngine` без копирования сторонних строк и regex;
- поддержан формат `common_strings` для правил: короткий `mode=any` и структурный `mode=all|any`;
- regex-правило без `common_strings` работает как раньше;
- regex-правило с `common_strings` запускается только после быстрого marker-check, если prefilter включен;
- дефолтные PHP, Bitrix, JavaScript и HTML regex-правила получили safe prefilter tokens;
- добавлена настройка `enable_common_strings_prefilter`, включенная по умолчанию;
- добавлен checkbox в настройках модуля;
- добавлены CLI-флаги `--enable-prefilter` и `--disable-prefilter`;
- состояние prefilter попадает в `ScanConfig`/JSON-конфиг отчета и CLI JSON payload;
- добавлен `tests/common_strings_prefilter_smoke.php`;
- `tests/cli_scan_smoke.php` проверяет полный CLI запуск с `--disable-prefilter`.

Ограничение на будущее:

- текущий prefilter применяется к анализируемому содержимому, которое может быть chunk/content текущего прохода, а не обязательно ко всему файлу;
- для текущих правил это допустимо, потому что маркер обычно находится рядом с regex-срабатыванием;
- для будущих сложных правил с `mode=all` нужно либо не использовать `all`, либо запускать такие правила на полном содержимом файла, чтобы не получить false negative на разнесенных маркерах.

#### [ ] Этап 10.3. `normalized_hash`

Цель: добавить нормализованный хэш контента для отчетов, baseline и будущих сравнений.

Задачи:

- реализовать собственную нормализацию контента;
- добавить `normalized_hash` в результат файла и JSON report;
- добавить настройку/CLI-флаг включения;
- покрыть smoke-тестом.

#### [ ] Этап 10.4. `FindingSuppressor`

Цель: централизованно подавлять false positive для всех будущих findings.

Задачи:

- вынести suppress-логику в отдельный сервис;
- поддержать подавление по file/hash/normalized_hash/signature/context/tags;
- сохранять suppressed findings в отчете отдельным состоянием;
- обновить UI whitelist/результатов;
- добавить CLI/JSON совместимость;
- покрыть smoke-тестом.

#### [ ] Этап 10.5. `EntropyAnalyzer`

Цель: добавить эвристический анализ энтропии для подозрительных payload.

Задачи:

- реализовать собственный analyzer без сторонних scoring-массивов;
- ограничить размер и количество анализируемых окон;
- добавить finding tags и JSON-поля;
- добавить настройки/CLI-флаги;
- покрыть smoke-тестом.

#### [ ] Этап 10.6. `UrlExtractor`

Цель: извлекать подозрительные URL/домены/IP из файлов и отчетов.

Задачи:

- реализовать собственный extractor;
- добавить URL entities в JSON report;
- связать URL с findings и tags;
- добавить UI-фильтрацию;
- добавить CLI/JSON совместимость;
- покрыть smoke-тестом.

#### [ ] Этап 10.7. Known Malware Hash Database

Цель: подключить собственную/пользовательскую базу известных hash-индикаторов.

Задачи:

- реализовать загрузчик пользовательской базы;
- не поставлять и не копировать сторонние malware hash database;
- поддержать file hash и normalized hash;
- добавить настройки/CLI-флаги;
- покрыть smoke-тестом на synthetic hash database.

#### [ ] Этап 10.8. WebShell Fingerprints

Цель: добавить собственные эвристики fingerprint-обнаружения web shell.

Задачи:

- реализовать fingerprint model без копирования сторонних fingerprints;
- использовать tags, entropy, URL и AST/Taint сигналы;
- добавить настройки/CLI-флаги;
- покрыть smoke-тестом на synthetic fixtures.

#### [ ] Этап 10.9. Baseline / Integrity Scanner

Цель: добавить пользовательский baseline целостности файлов.

Задачи:

- создать baseline storage;
- поддержать create/update/compare;
- использовать file hash и normalized hash;
- отразить статусы new/changed/deleted/restored;
- добавить UI и CLI;
- добавить JSON report секцию integrity;
- покрыть smoke-тестом.

#### [ ] Этап 10.10. `AgentScanner`

Цель: анализировать Bitrix agents как DB-backed источник подозрительного кода.

Задачи:

- читать agents через Bitrix API;
- анализировать payload через существующие RuleEngine/AST/Taint там, где применимо;
- использовать tags и suppress;
- добавить настройки/CLI-флаги;
- покрыть smoke-тестом с mock/fake Bitrix data layer.

#### [ ] Этап 10.11. `EventHandlerScanner`

Цель: анализировать зарегистрированные обработчики событий Bitrix.

Задачи:

- извлекать event handlers через Bitrix API;
- проверять suspicious callbacks и payload;
- использовать RuleEngine/AST/Taint, tags и suppress;
- добавить настройки/CLI-флаги;
- покрыть smoke-тестом.

#### [ ] Этап 10.12. `TemplateConditionScanner`

Цель: анализировать условия шаблонов и DB-backed PHP fragments.

Задачи:

- определить безопасный перечень Bitrix-сущностей для чтения;
- анализировать условия через существующие detector-слои;
- использовать tags и suppress;
- добавить настройки/CLI-флаги;
- покрыть smoke-тестом.

#### [ ] Этап 10.13. `DbTriggerScanner`

Цель: анализировать DB triggers/procedural fragments там, где доступно и применимо.

Задачи:

- реализовать read-only сбор метаданных;
- не выполнять DB code;
- добавить отдельные findings/tags;
- добавить настройки/CLI-флаги;
- покрыть smoke-тестом.

#### [ ] Этап 10.14. `CoreIntegrityChecker` Bitrix

Цель: отдельно от пользовательского baseline проверять целостность ядра Bitrix.

Задачи:

- реализовать отдельный checker;
- не смешивать с пользовательским baseline;
- использовать только легальные источники контрольной информации;
- добавить настройки/CLI-флаги;
- добавить JSON report секцию core integrity;
- покрыть smoke-тестом.

## MVP Definition of Done

MVP считается готовым, когда:

- [x] модуль устанавливаемой структуры создан;
- [x] настройки сохраняются;
- [x] scanner engine выделен в классы;
- [x] сканирование запускается через AJAX endpoint;
- [x] прогресс доступен в UI;
- [ ] результаты полноценно отображаются;
- [x] quarantine работает;
- [x] dry-run работает для quarantine action;
- [x] dry-run работает для delete action;
- [x] CLI scan runner работает;
- [x] базовые права и `sessid` проверяются в AJAX;
- [ ] права уровней `D/R/W/X` реализованы полностью;
- [ ] uninstall проверен на стенде;
- [ ] документация и changelog готовы.

## Правила разработки

- Один крупный этап — отдельный PR.
- Не возвращать корневой CLI в этот проект.
- Не добавлять Composer на первом этапе.
- Не копировать код из сторонних модулей.
- Не копировать код, сигнатуры, regex, fingerprints, malware hash database, тексты сообщений, scoring-массивы и структуру классов Bitrix Security, Wordfence или других сторонних решений.
- `/reference` использовать только как reference-only источник идей, типов проверяемых сущностей, сценариев обнаружения и категорий риска.
- Scanner engine не должен писать HTML.
- UI не должен содержать detector logic.
- Любое destructive action должно иметь dry-run и подтверждение.
- После каждого этапа запускать PHP syntax check.

## Ближайший следующий шаг

Этап 10.3: `normalized_hash`.

Начать с проектирования нормализации контента и добавления `normalized_hash` в результат файла, JSON-отчет и будущий baseline.
