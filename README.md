# PHP Antivirus Scanner

## Overview
This script is a command-line malware scanner written in PHP. It recursively scans directories and files, detects potential threats using predefined virus signatures, and generates logs based on the findings.

## Features
- Recursively scans directories and files for malware signatures.
- Detects encoded malware patterns (e.g., Base64, hex-encoded payloads, obfuscated PHP code).
- Logs scan results in either verbose or short mode.
- Option to save logs to a file.
- Option to load your own virus signatures from a file.
- Option to get log in json

## Requirements
- PHP 7.4 or higher
- CLI (Command-Line Interface) mode enabled for PHP

## Installation
No installation is required. Simply place the `antivirus.php` script in a desired directory and execute it via the command line.

## Usage
Run the script with the following parameters:
```sh
php antivirus.php --path=/path/to/scan [--signatures-file=/path/to/signatures.txt] [--log-mode=verbose|short] [--exclude-dir="/cache/,/temp/"] [--log-file=/path/to/logfile.log]
```

### Parameters
- `--path` *(required)*: The directory or file path to scan.
- `--signatures-file` *(optional)*: The file with virus signatures.
- `--log-mode` *(optional)*: Logging mode (`verbose` for detailed output, `short` for infected files only). Default: `short`.
- `--exclude-dir` *(optional)*: Comma-separated list of directory patterns to exclude from scanning.
- `--log-file` *(optional)*: Path to a file where logs will be saved.

### Example Commands
Scan a directory with verbose output:
```sh
php antivirus.php --path=/var/www --log-mode=verbose
```

Scan a directory excluding `/upload/` and `/temp/` directories:
```sh
php antivirus.php --path=/var/www --log-mode=verbose --exclude-dir="/upload/,/temp/"
```

Save logs to a file:
```sh
php antivirus.php --path=/var/www --log-file=/var/log/antivirus.log
```

Load own virus signatures from a file:
```sh
php antivirus.php --path=/var/www --signatures-file=sdignatures.txt
```

## Exit Codes
- `0` - No threats found.
- `1` - Threats detected.
- `2` - Error occurred.

## License
This script is released under the MIT License.

## Disclaimer
This script is a basic signature-based scanner and does not replace commercial antivirus solutions. Always use additional security measures to protect your server.

