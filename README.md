# PHP Antivirus CLI Malware Scanner

**PHP Antivirus** — это консольный middleware/utility-скрипт для базовой проверки файлов и директорий на признаки вредоносного кода с помощью регулярных выражений-сигнатур. Проект ориентирован на DevOps- и backend-сценарии: ручная проверка web-root, интеграция в cron, CI/CD pipeline, pre-deploy проверки и первичный аудит подозрительных файлов.

> Текущая версия в исходном коде: **1.0**  
> Лицензия: **MIT**  
> Автор: **Roman Tarasenko**

---

## Возможности

- Рекурсивное сканирование директорий.
- Сканирование отдельного файла.
- Проверка только заданного набора расширений.
- Встроенный набор сигнатур для поиска типичных вредоносных конструкций.
- Поддержка внешнего файла сигнатур.
- Проверка валидности regex-сигнатур перед использованием.
- Обнаружение подозрительных PHP/JS/web-shell паттернов:
  - `eval`, `assert`, `base64_decode`, `shell_exec`, `system`, `passthru`, `proc_open`, `pcntl_exec`;
  - `create_function`, `call_user_func`, `curl_exec`, `fsockopen`, `gzuncompress`, `str_rot13`;
  - подозрительные `<script>`, `<iframe>`, `<object>`, `<embed>`;
  - формы, похожие на phishing/login/banking/paypal/wallet страницы;
  - запись входящего потока `php://input`;
  - устаревший и опасный `preg_replace(... /e ...)`;
  - загрузка файлов через `move_uploaded_file`/`copy` из `$_FILES`.
- Пропуск известных бинарных форматов по magic bytes.
- Обработка больших файлов чанками.
- Краткий и подробный режим логирования.
- Запись логов в файл.
- JSON-отчёт для автоматизированной обработки.
- Перемещение найденных угроз в карантин.
- Генерация JSON metadata-файла для каждого объекта в карантине.
- Корректные exit codes для использования в shell/CI/CD.

---

## Требования

- PHP **7.4+** или PHP **8.x**.
- CLI-доступ к PHP.
- Права на чтение сканируемых файлов.
- Права на запись, если используется лог-файл или карантин.

Проверить версию PHP:

```bash
php -v
```

---

## Установка

Склонируйте репозиторий или скачайте файл `antivirus.php`:

```bash
git clone https://github.com/Roman2004de/php-antivirus.git
cd php-antivirus
```

Скрипт не требует Composer-зависимостей и запускается напрямую через PHP CLI.

---

## Быстрый старт

Сканирование директории:

```bash
php antivirus.php --path=/var/www/html
```

Сканирование одного файла:

```bash
php antivirus.php --path=/var/www/html/index.php
```

Подробный вывод:

```bash
php antivirus.php --path=/var/www/html --log-mode=verbose
```

JSON-отчёт:

```bash
php antivirus.php --path=/var/www/html --json-report
```

Сохранение логов:

```bash
php antivirus.php --path=/var/www/html --log-file=/var/log/php-antivirus.log
```

Перемещение найденных угроз в карантин:

```bash
php antivirus.php --path=/var/www/html --quarantine=/var/quarantine/php-antivirus
```

Использование внешнего файла сигнатур:

```bash
php antivirus.php \
  --path=/var/www/html \
  --signatures-file=/opt/php-antivirus/signatures.txt
```

---

## CLI-параметры

| Параметр | Обязательный | Значение по умолчанию | Описание |
|---|---:|---|---|
| `--path` | Да | — | Путь к файлу или директории для сканирования. |
| `--signatures-file` | Нет | встроенные сигнатуры | Путь к внешнему файлу regex-сигнатур. |
| `--log-mode` | Нет | `short` | Режим логирования: `short` или `verbose`. |
| `--log-file` | Нет | не используется | Путь к файлу для записи логов. |
| `--quarantine` | Нет | не используется | Директория, куда будут перемещены найденные угрозы. |
| `--json-report` | Нет | `false` | Вывод результата в JSON-формате. |

Справка выводится автоматически, если не передан обязательный параметр `--path`:

```bash
php antivirus.php
```

---

## Режимы логирования

### `short`

Режим по умолчанию. Показывает только ошибки, найденные угрозы и финальный результат.

```bash
php antivirus.php --path=/var/www/html --log-mode=short
```

### `verbose`

Подробный режим. Показывает процесс обхода директорий и проверки файлов.

```bash
php antivirus.php --path=/var/www/html --log-mode=verbose
```

---

## JSON-отчёт

При использовании `--json-report` итоговый результат выводится в `STDOUT` в формате JSON.

Пример:

```json
{
    "total_scanned": 128,
    "threats_found": 2,
    "runtime_errors": 0,
    "infected_files": [
        "/var/www/html/upload/shell.php",
        "/var/www/html/cache/backdoor.phtml"
    ]
}
```

Логи и ошибки при включённом JSON-режиме пишутся в `STDERR`, чтобы не ломать JSON-вывод и позволить безопасно парсить результат в CI/CD или shell-скриптах.

---

## Внешний файл сигнатур

Файл сигнатур должен содержать по одной regex-сигнатуре на строку.

Пример `signatures.txt`:

```txt
/\beval\s*\(/i
/\bbase64_decode\s*\(/i
/file_put_contents\s*\(\s*["']php:\/\/input["']\s*,/i
/<\s*iframe\b/i
```

Запуск с внешними сигнатурами:

```bash
php antivirus.php \
  --path=/var/www/html \
  --signatures-file=./signatures.txt
```

Если внешний файл сигнатур не передан или не найден, скрипт использует встроенный набор сигнатур.

> Важно: каждая сигнатура должна быть валидным PHP PCRE-выражением, включая разделители, например `/pattern/i`.

---

## Поддерживаемые расширения для сканирования

Скрипт сканирует только файлы с расширениями из внутреннего allowlist:

```txt
php, js, phtml, phtm, cgi, pl, o, so, py, sh,
php3, php4, php5, php6, php7, pht, shtml,
susp, suspected, infected, vir, html, htm, tpl,
inc, css, txt, sql, svg, htaccess
```

Файлы с другими расширениями при рекурсивном сканировании директорий пропускаются.

---

## Пропуск бинарных файлов

Перед чтением содержимого скрипт проверяет сигнатуру начала файла и пропускает известные бинарные форматы:

- `exe`
- `png`
- `jpg`
- `zip`
- `pdf`
- `rar`
- `gif`
- `elf`
- `mp3`
- `mp4`

Это снижает количество ложных срабатываний и уменьшает нагрузку при сканировании web-директорий.

---

## Обработка больших файлов

Файлы размером больше **100 MB** не читаются целиком в память. Вместо этого используется блочная обработка:

- размер блока: **32 KB**;
- между блоками сохраняется хвост буфера в **512 байт**, чтобы не пропустить сигнатуру на границе чанков.

---

## Карантин

Если передан параметр `--quarantine`, каждый найденный подозрительный файл перемещается в указанную директорию.

Пример:

```bash
php antivirus.php \
  --path=/var/www/html \
  --quarantine=/var/quarantine/php-antivirus
```

Для каждого файла формируется безопасное уникальное имя:

```txt
YYYYMMDD_HHMMSS_<sha256-prefix>_<original-filename>
```

Рядом создаётся metadata-файл:

```txt
YYYYMMDD_HHMMSS_<sha256-prefix>_<original-filename>.json
```

Пример metadata:

```json
{
    "original_path": "/var/www/html/upload/shell.php",
    "quarantined_path": "/var/quarantine/php-antivirus/20250201_120000_abcd1234ef567890_shell.php",
    "sha256": "abcd1234...",
    "quarantined_at": "2025-02-01T12:00:00+00:00",
    "original_name": "shell.php"
}
```

---

## Exit codes

Скрипт использует exit codes, чтобы его можно было безопасно применять в автоматизации.

| Код | Константа | Значение |
|---:|---|---|
| `0` | `EXIT_CLEAN` | Угрозы не найдены, ошибок выполнения нет. |
| `1` | `EXIT_THREATS_FOUND` | Найдены подозрительные или заражённые файлы. |
| `2` | `EXIT_CLI_ERROR` | Ошибка CLI-вызова, например не передан `--path`. |
| `3` | `EXIT_RUNTIME_ERROR` | Критическая runtime-ошибка, например путь не существует. |
| `4` | `EXIT_PARTIAL_ERROR` | Сканирование завершено, но были runtime-ошибки чтения/обхода. |

Пример использования в bash:

```bash
php antivirus.php --path=/var/www/html --json-report > report.json
status=$?

case "$status" in
  0)
    echo "Clean"
    ;;
  1)
    echo "Threats found"
    ;;
  2)
    echo "CLI usage error"
    ;;
  3)
    echo "Runtime error"
    ;;
  4)
    echo "Partial scan error"
    ;;
esac
```

---

## Примеры DevOps-интеграции

### Cron-задача

Ежедневное сканирование web-root с логированием:

```cron
0 3 * * * /usr/bin/php /opt/php-antivirus/antivirus.php --path=/var/www/html --log-file=/var/log/php-antivirus.log --quarantine=/var/quarantine/php-antivirus
```

### CI/CD pipeline

Пример для shell-шага:

```bash
php antivirus.php --path="$CI_PROJECT_DIR" --json-report > antivirus-report.json
status=$?

if [ "$status" -eq 1 ]; then
  echo "Malware signatures detected. Check antivirus-report.json"
  exit 1
fi

if [ "$status" -ge 2 ]; then
  echo "Antivirus scan failed with status: $status"
  exit "$status"
fi
```

### Pre-deploy проверка

```bash
php antivirus.php --path=./public --log-mode=verbose
```

---

## Рекомендации по эксплуатации

- Запускайте сканирование от пользователя с минимально необходимыми правами.
- Для production-серверов используйте `--log-file`, чтобы сохранять историю проверок.
- Для автоматизации используйте `--json-report` и exit codes.
- Перед включением `--quarantine` убедитесь, что директория карантина находится вне web-root.
- Не удаляйте подозрительные файлы автоматически без ручной проверки.
- Регулярно обновляйте внешний файл сигнатур.
- После обнаружения угроз проверяйте логи веб-сервера, access logs, upload-директории и историю деплоя.

---

## Ограничения

Этот скрипт является сигнатурным сканером и не заменяет полноценные EDR/AV/WAF-решения.

Текущие ограничения:

- Нет поведенческого анализа.
- Нет sandbox-исполнения подозрительного кода.
- Нет AST-парсинга PHP/JS.
- Нет декодирования вложенной обфускации перед проверкой.
- Нет автоматического восстановления файлов из карантина.
- Возможны ложные срабатывания на легитимный код, использующий опасные функции.
- Возможны пропуски новых или сильно обфусцированных угроз.
- При сканировании директории учитываются только расширения из allowlist.

---

## Безопасность

Найденное совпадение означает, что файл содержит подозрительный паттерн, а не обязательно является вредоносным. Всегда выполняйте ручную проверку перед удалением или окончательной блокировкой файла.

Особое внимание стоит уделять файлам, содержащим:

- динамическое выполнение кода;
- вызовы shell-команд;
- сетевые функции;
- загрузку и перемещение пользовательских файлов;
- запись в `php://input`;
- обфускацию через base64/gzip/rot13;
- HTML/JS-вставки в неожиданных местах.

---

## Структура проекта

Минимальная структура:

```txt
php-antivirus/
├── antivirus.php
├── signatures.txt
└── README.md
```

Где:

- `antivirus.php` — основной CLI-скрипт сканера;
- `signatures.txt` — опциональный внешний файл сигнатур;
- `README.md` — документация проекта.

---

## Roadmap

Потенциальные направления развития:

- Добавить режим `--delete` для удаления после подтверждения.
- Добавить restore-команду для восстановления из карантина.
- Добавить конфигурационный файл `config.json` или `config.yaml`.
- Добавить исключения директорий и файлов.
- Добавить настройку списка расширений через CLI.
- Добавить severity-level для сигнатур.
- Добавить structured JSONL logs.
- Добавить unit-тесты для regex-сигнатур и quarantine logic.
- Добавить GitHub Actions workflow для проверки pull requests.
- Добавить поддержку Composer-пакета.

---

## Лицензия

Проект распространяется под лицензией **MIT**.

---

## Disclaimer

Инструмент предназначен для первичного анализа и автоматизированной проверки файлов на известные подозрительные паттерны. Используйте его как дополнительный слой защиты, а не как единственный механизм безопасности.
