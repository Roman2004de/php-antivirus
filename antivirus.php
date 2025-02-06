<?php
/**
 * PHP Antivirus: Command-Line Malware Scanner
 * Version: 1.0
 * License: MIT
 *
 * @author Roman Tarasenko
 * @github https://github.com/Roman2004de/php-antivirus
 */

class Antivirus {
    private $logMode = 'short';
    private $infectedFiles = [];
    private $totalScanned = 0;
    private $logFile = null;
    private $quarantinePath = null;
    private $outputJson = false;
    private $blockSize = 32768; // 32KB
    private $maxFileSize = 104857600; // 100MB
    private $extensions = ['php', 'js', 'phtml', 'phtm', 'cgi', 'pl', 'o', 'so', 'py', 'sh', 'phtml', 'php3', 'php4', 'php5', 'php6', 'php7', 'pht', 'shtml', 'susp', 'suspected', 'infected', 'vir', 'html', 'htm', 'tpl', 'inc', 'css', 'txt', 'sql']; // File extensions to scan
    private $signaturesFile = null;

    private $virusSignatures = [];
    private $binaryFormats = [ // binary Files to skip scanning
        'exe' => "\x4D\x5A",          // MZ
        'png' => "\x89\x50\x4E\x47",  // PNG
        'jpg' => "\xFF\xD8\xFF",      // JPEG
        'zip' => "\x50\x4B\x03\x04",  // ZIP
        'pdf' => "\x25\x50\x44\x46",  // PDF document
        'rar' => "\x52\x61\x72\x21",  // RAR archive
        'gif' => "\x47\x49\x46\x38",  // GIF image
        'elf' => "\x7F\x45\x4C\x46",  // Linux Executable (ELF)
        'mp3' => "\x49\x44\x33",      // MP3 audio
        'mp4' => "\x00\x00\x00\x18\x66\x74\x79\x70" // MP4 video
    ];

    public function __construct($logMode, $signaturesFile = null, $logFile = null, $quarantinePath = null, $outputJson = false) {
        $this->logMode = $logMode;
        $this->logFile = $logFile;
        $this->quarantinePath = $quarantinePath;
        $this->outputJson = $outputJson;
        $this->signaturesFile = $signaturesFile;

        $this->loadSignatures();
    }

    private function loadSignatures() {
        if (!empty($this->signaturesFile) && file_exists($this->signaturesFile)) {
            try {
                $this->virusSignatures = array_map('trim', file($this->signaturesFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));
            } catch (Exception $e) {
                $this->log("Error loading virus signatures: " . $e->getMessage(), true);
            }
        } else {
            $this->virusSignatures = [
                '<\s*script|<\s*iframe|<\s*object|<\s*embed|fromCharCode|setTimeout|setInterval|location\.|document\.|window\.|navigator\.|\$(this)\.',
                '<\s*title|<\s*html|<\s*form|<\s*body|bank|account',
                '<\?php|<\?=|#!/usr|#!/bin|eval|assert|base64_decode|system|passthru|proc_open|pcntl_exec|shell_exec|create_function|exec|socket_create|curl_exec|curl_multi_exec|popen|fwrite|fputs|file_get_|call_user_func|file_put_|\$_REQUEST|ob_start|\$_GET|\$_POST|\$_SERVER|\$_FILES|move|copy|array_|reg_replace|mysql_|chr|fsockopen|\$GLOBALS|sqliteCreateFunction', // potentially dangerous functions
                '/base64_decode\s*\(/i',
                '/gzuncompress\s*\(/i',
                '/str_rot13\s*\(/i',
                '/\$_(GET|POST|REQUEST|COOKIE)\s*\[.*\]\s*\(\$/',
                '/\x75\x6E\x61\x6D\x65\x28\x29\x20\x7B\x20\x7D/i',
                '/assert\s*\(/i', // execute commands using assert
                '/file_put_contents\s*\(\s*["\']php:\/\/input["\']\s*,/i', // web shell
                '/\b(eval|system|shell_exec|popen|exec|passthru|proc_open|pcntl_exec)\s*\(/i', // potentially dangerous functions (short list)
                '/preg_replace\s*\(\s*[\'"].*\/e[\'"]\s*,/i', // execute code using modifier `/e`
                '/\b(move_uploaded_file|copy)\s*\(\s*\$_FILES\s*\[\s*[\'"].*[\'"]\s*\]\s*\[\s*[\'"]tmp_name[\'"]\s*\]/i' // bypass file downloads
            ];
        }
    }

    public function scan($path) {
        if (!file_exists($path)) {
            $this->log("Error: Path $path does not exist!", true);
            exit(1);
        }

        $this->log("Starting scan: $path");
        
        if (is_dir($path)) {
            $this->scanDirectory($path);
        } else {
            $this->totalScanned++;
            $this->checkFile($path);
        }

        $this->showResults();
    }

    private function showResults() {
        if ($this->outputJson) {
            echo json_encode([
                'total_scanned' => $this->totalScanned,
                'threats_found' => count($this->infectedFiles),
                'infected_files' => $this->infectedFiles
            ], JSON_PRETTY_PRINT);
        } else {
            $this->log("\nScan complete!");
            $this->log("Total files scanned: " . $this->totalScanned);
            $this->log("Threats found: " . count($this->infectedFiles));
        }

        if (!empty($this->infectedFiles)) {
            foreach ($this->infectedFiles as $file) {
                $this->log(" - $file", true);
                if ($this->quarantinePath) {
                    $this->moveToQuarantine($file);
                }
            }
            exit(1);
        }
        exit(0);
    }

    private function scanDirectory($directory) {
        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );

            foreach ($iterator as $file) {
                if ($file->isDir()) {
                    $this->log("Scanning directory: " . $file->getRealPath());
                    continue;
                }

                if (!in_array($file->getExtension(), $this->extensions)) {
                    continue; 
                }

                $this->totalScanned++;
                $this->checkFile($file->getRealPath());
            }
        } catch (Exception $e) {
            $this->log("Error scanning directory: " . $e->getMessage(), true);
        }
    }

    private function checkFile($file) {
        $this->log("Checking: $file");

        if ($this->isBinaryFile($file)) {
            $this->log("Skipping binary file: $file");
            return;
        }

        $size = @filesize($file);
        if ($size > $this->maxFileSize) {
            $this->processLargeFile($file);
            return;
        }

        $content = file_get_contents($file);
        $this->checkContent($content, $file);
    }

    private function processLargeFile($file) {
        $this->log("Processing large file: $file");
        $handle = fopen($file, 'rb');
        $buffer = '';

        while (!feof($handle)) {
            $buffer .= fread($handle, $this->blockSize);
            $this->checkContent($buffer, $file);
            $buffer = substr($buffer, -512);
        }
        fclose($handle);
    }

    private function checkContent($text, $file) {
        foreach ($this->virusSignatures as $signature) {
            if (preg_match($signature, $text)) {
                $this->infectedFiles[] = $file;
                $this->log("Threat detected in: $file", true);
                return;
            }
        }
    }

    private function isBinaryFile($file) {
        $header = file_get_contents($file, false, null, 0, 4);
        foreach ($this->binaryFormats as $signature) {
            if (strpos($header, $signature) === 0) return true;
        }
        return false;
    }

    private function moveToQuarantine($file) {
        $destination = $this->quarantinePath . '/' . basename($file);
        rename($file, $destination);
        $this->log("Moved to quarantine: $destination", true);
    }

    private function log($message, $isError = false) {
        if ($this->logMode === 'verbose' || $isError) {
            $logMessage = date('[Y-m-d H:i:s] ') . $message . PHP_EOL;
            echo $logMessage;

            if ($this->logFile) {
                file_put_contents($this->logFile, $logMessage, FILE_APPEND);
            }
        }
    }
}

// Command-line processing
$options = getopt('', ['path:', 'signatures-file:', 'log-mode:', 'log-file:', 'quarantine:', 'json-report']);

if (!isset($options['path'])) {
    echo "Usage:\n";
    echo "php antivirus.php --path=/path/to/scan [--signatures-file=/path/to/signatures.txt] [--log-mode=verbose|short] [--log-file=/path/to/log.txt] [--quarantine=/path/to/quarantine] [--json-report]\n";
    exit(1);
}

$signaturesFile = $options['signatures-file'] ?? null;
$logMode = $options['log-mode'] ?? 'short';
$logFile = $options['log-file'] ?? null;
$quarantinePath = $options['quarantine'] ?? null;
$outputJson = isset($options['json-report']);

$antivirus = new Antivirus($logMode, $signaturesFile, $logFile, $quarantinePath, $outputJson);
$antivirus->scan(rtrim($options['path'], '/'));
