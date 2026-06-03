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
- Версия: `0.0.1`
- Партнер: `Цифровой Элемент`
- URI партнера: `https://d-element.ru`
- Namespace: `Delement\Antivirus`
- Composer: не использовать на первом этапе
- Интерфейс: русский и английский

## Текущий статус

Стадия: MVP с работающим сканированием, отчетами и карантином.

Уже есть устанавливаемый skeleton, настройки, модульный scanner engine, AJAX-пошаговое сканирование, results storage/UI, RU/EN локализация и базовый карантин с восстановлением.

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
- поля: scan path, profile, action, dry-run, quarantine path, exclusions, batch size, max file size;
- дефолты в `default_option.php`;
- проверка `sessid`;
- базовая валидация путей, диапазонов и действия;
- запрет сохранить `delete` без `dry-run` до реализации подтверждений.

Acceptance:

- [x] настройки сохраняются;
- [x] настройки загружаются;
- [x] значения валидируются;
- [x] можно сбросить настройки к значениям по умолчанию;
- [ ] форма проверена на живом Bitrix-стенде.

### [x] Этап 3. Scanner engine extraction

Цель: вынести scanner engine в reusable-классы модуля.

Сделано:

- создан `Delement\Antivirus\Config\ScanConfig`;
- создан `Delement\Antivirus\Scanner\Scanner`;
- создан файловый слой `FileCollector`, `FileFilter`, `FileReader`, `FileTypeDetector`;
- создан detection слой `Detector`, `RuleEngine`, `SignatureLoader`;
- созданы DTO `ScanResult`, `ScanSummary`, `Finding`;
- добавлены `Severity` и `Verdict`;
- добавлены правила в `lib/Rules`: PHP, JavaScript, HTML, Bitrix-specific;
- scanner не зависит от UI;
- scanner не вызывает `echo` и `exit`;
- добавлен `tests/engine_smoke.php`.

Acceptance:

- [x] scanner работает без UI;
- [x] scanner возвращает структурированный результат;
- [x] scanner не пишет HTML;
- [x] smoke-test находит PHP-файл внутри `/upload/`;
- [ ] нужен набор unit/integration tests для правил и false positives.

### [x] Этап 4. AJAX scan

Цель: сделать порционное сканирование из админки.

Сделано:

- `admin/ajax.php` подключает модуль и передает запросы в controller;
- создан `Delement\Antivirus\Admin\AjaxController`;
- создан `Delement\Antivirus\Scanner\ScanSessionStore`;
- реализованы actions: `ping`, `start_scan`, `scan_step`, `get_status`, `cancel_scan`;
- scan sessions сохраняются в writable runtime-каталог `/bitrix/tmp/delement.antivirus/sessions`;
- JSON reports сохраняются в writable runtime-каталог `/bitrix/tmp/delement.antivirus/reports`;
- отмененное сканирование сохраняет частичный JSON report со статусом `cancelled`;
- UI страницы сканирования показывает прогресс, статус, счетчики и текущий файл;
- JS крутит `scan_step` до `finished` или `cancelled`.

Acceptance:

- [x] endpoint проверяет авторизацию, права и `sessid`;
- [x] scan выполняется порциями;
- [x] есть cancel;
- [x] есть JSON report;
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
- restore не перезаписывает существующий файл;
- поддержан restore;
- поддержано удаление payload из карантина;
- добавлен рабочий `admin/quarantine.php`;
- destructive actions требуют права `W`, POST, `sessid` и подтверждение для удаления;
- `dry-run` не меняет файловую систему и сохраняет только планируемое действие;
- добавлен `tests/quarantine_smoke.php`.

Осталось улучшить:

- добавить отдельный audit log действий restore/delete;
- добавить переходы между отчетом и записью карантина;
- добавить фильтры/поиск по карантину.

Acceptance:

- [x] файлы не перезаписываются;
- [x] metadata создается;
- [x] restore работает;
- [x] dry-run не меняет файловую систему;
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

### [ ] Этап 8. Cron runner

Цель: добавить запуск по расписанию.

Задачи:

- доработать `install/tools/scan.php`;
- подключить Bitrix prolog;
- читать настройки модуля;
- поддержать CLI args: profile, path, json, dry-run;
- запускать scanner engine;
- сохранять report;
- возвращать корректный exit code.

Acceptance:

- [ ] scan запускается из CLI;
- [ ] report сохраняется;
- [ ] exit code корректный;
- [ ] вывод JSON не ломается логами.

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
- [ ] cron runner работает;
- [x] базовые права и `sessid` проверяются в AJAX;
- [ ] права уровней `D/R/W/X` реализованы полностью;
- [ ] uninstall проверен на стенде;
- [ ] документация и changelog готовы.

## Правила разработки

- Один крупный этап — отдельный PR.
- Не возвращать корневой CLI в этот проект.
- Не добавлять Composer на первом этапе.
- Не копировать код из сторонних модулей.
- Scanner engine не должен писать HTML.
- UI не должен содержать detector logic.
- Любое destructive action должно иметь dry-run и подтверждение.
- После каждого этапа запускать PHP syntax check.

## Ближайший следующий шаг

Этап 8: `Cron runner`.

Начать с доработки `install/tools/scan.php`: чтение настроек модуля, запуск scanner engine, сохранение отчета и корректные exit codes.
