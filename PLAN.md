# План разработки delement.antivirus

Модуль 1С-Битрикс Marketplace **«Интеллектуальный поиск вирусов и троянов»**.

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
- Интерфейс: русский

## Текущий статус

Стадия: ранний MVP.

Уже есть устанавливаемый skeleton, настройки, модульный scanner engine и AJAX-пошаговое сканирование. Следующий крупный блок: results UI и нормальная модель результатов.

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
- scan sessions сохраняются в `var/sessions`;
- JSON reports сохраняются в `var/reports`;
- UI страницы сканирования показывает прогресс, статус, счетчики и текущий файл;
- JS крутит `scan_step` до `finished` или `cancelled`.

Acceptance:

- [x] endpoint проверяет авторизацию, права и `sessid`;
- [x] scan выполняется порциями;
- [x] есть cancel;
- [x] есть JSON report;
- [ ] сценарий проверен в браузере на живом Bitrix-стенде;
- [ ] нужно добавить обработку больших объемов результатов без раздувания session JSON.

### [ ] Этап 5. Results UI

Цель: показать результаты сканирования в админке.

Задачи:

- реализовать `admin/results.php`;
- читать reports из `var/reports`;
- сделать список последних сканов;
- сделать таблицу findings;
- добавить фильтры по status, severity, category, signature;
- добавить просмотр деталей finding;
- добавить экспорт JSON;
- экранировать excerpts и пути;
- подготовить переход из scan page на results page.

Acceptance:

- [ ] результаты доступны после скана;
- [ ] видно file, score, severity, category, signature, excerpt;
- [ ] можно фильтровать malicious/suspicious;
- [ ] экспорт JSON доступен;
- [ ] большие фрагменты файлов не выводятся без escaping.

### [ ] Этап 6. Quarantine

Цель: сделать безопасный карантин.

Задачи:

- создать `QuarantineManager`;
- реализовать quarantine action;
- сохранить metadata JSON;
- считать SHA256;
- не перезаписывать файлы;
- поддержать restore;
- поддержать permanent delete;
- добавить `admin/quarantine.php`;
- логировать destructive actions;
- учитывать dry-run.

Acceptance:

- [ ] файлы не перезаписываются;
- [ ] metadata создается;
- [ ] restore работает;
- [ ] dry-run не меняет файловую систему;
- [ ] destructive actions требуют права уровня `X` и подтверждение.

### [ ] Этап 7. Whitelist

Цель: снизить false positives.

Задачи:

- создать `Whitelist`;
- реализовать whitelist по path;
- реализовать whitelist по regex path;
- реализовать whitelist по hash;
- реализовать whitelist по signature id;
- реализовать исключение `file + signature id`;
- добавить UI actions из results page.

Acceptance:

- [ ] файл можно добавить в whitelist;
- [ ] конкретную сигнатуру можно исключить для файла;
- [ ] whitelist учитывается при scan;
- [ ] пользовательские regex валидируются перед сохранением.

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

- вынести все тексты в `lang/ru`;
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
- [ ] quarantine работает;
- [ ] dry-run работает для destructive actions;
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

Этап 5: `Results UI`.

Начать с чтения JSON reports из `var/reports`, списка последних сканов и таблицы findings в `admin/results.php`.
