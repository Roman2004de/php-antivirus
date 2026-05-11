# PHP Antivirus — Refactoring Plan

## 📌 Project Status (Baseline)

- CLI-антивирус на PHP (один файл)
- Рекурсивное сканирование директорий
- Сигнатурный анализ (regex)
- Поддержка verbose/short, JSON, quarantine

### Проблемы
- некорректные regex
- false positives
- нет структуры
- нет whitelist
- нет scoring

---

## 🎯 Цель

Production-ready CLI инструмент:
- расширяемый
- объяснимый
- с whitelist и профилями

---

## ⚙️ Зафиксированные решения

- Структура: несколько файлов  
- CLI: совместимость сохраняем  
- PHP: 7.4  
- Composer: нет  
- Профиль: настраиваемый  
- Удаление: настраиваемое  
- Типы: php, phtml, js, html, htm, svg, htaccess  
- Whitelist: да  
- Многопоточность: позже  
- Цель: production  

---

## 🧱 Структура

project/
  antivirus.php
  src/
  config/
  var/

---

## 🧠 Модель

rules → findings → score → verdict

---

## 📊 Результат

- file
- status
- score
- findings

---

## 🚦 Статусы

clean / skipped / low_risk / suspicious / malicious / error

---

## ⚖️ Scoring

eval +5  
base64 +2  
system +4  

---

## 🧪 Профили

balanced / strict / paranoid

---

## 📂 Whitelist

paths / patterns / hashes / exceptions

---

## ⚙️ Режимы

report / quarantine / delete / dry-run

---

# 🚧 План

## Фаза 1
1. Разделение файлов ⬜  
2. Сигнатуры ⬜  
3. Findings ⬜  
4. Regex fix ⬜  

## Фаза 2
5. Scoring ⬜  
6. Категории ⬜  
7. Эвристики ⬜  
8. Whitelist ⬜  

## Фаза 3
9. CLI ⬜  
10. Отчеты ⬜  
11. Quarantine ⬜  
12. Exit codes ⬜  

## Фаза 4
13. Оптимизация ⬜  
14. Кэш ⬜  
15. Многопоточность ⬜  

---

## 📍 Статус

BEFORE REFACTOR  
Next: Step 1
