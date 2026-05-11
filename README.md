# PHP Antivirus Scanner

## Overview

PHP Antivirus Scanner is a command-line malware scanner written in PHP.

The scanner recursively scans directories and files, detects suspicious or potentially malicious code using predefined signatures, and reports findings in either text or JSON format.

The project is focused on scanning typical web application files and detecting:

- suspicious PHP execution functions
- obfuscated payloads
- encoded malware
- suspicious JavaScript
- common webshell indicators

---

## Features

- Recursive directory scanning
- Signature-based malware detection
- Detection of encoded/obfuscated payloads
- Verbose and short logging modes
- JSON report support
- External signature file support
- Quarantine support
- Runtime error tracking
- Clean JSON output for automation/CI usage

---

## Supported File Types

The scanner is currently focused on:

- `php`
- `phtml`
- `js`
- `html`
- `htm`
- `svg`
- `htaccess`

---

## Requirements

- PHP 7.4 or higher
- PHP CLI enabled

---

## Installation

No installation is required.

Simply place the `antivirus.php` script in a directory and run it from the command line.

---

## Usage

```sh
php antivirus.php --path=/path/to/scan [options]