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
    private $extensions = ['php', 'js', 'phtml', 'phtm', 'cgi', 'pl', 'o', 'so', 'py', 'sh', 'phtml', 'php3', 'php4', 'php5', 'php6', 'php7', 'pht', 'shtml', 'susp', 'suspected', 'infected', 'vir', 'html', 'htm', 'tpl', 'inc', 'css', 'txt', 'sql', 'svg', 'htaccess']; // File extensions to scan
    private $signaturesFile = null;

    private $runtimeErrors = 0;

    const EXIT_CLEAN = 0;
    const EXIT_THREATS_FOUND = 1;
    const EXIT_CLI_ERROR = 2;
    const EXIT_RUNTIME_ERROR = 3;
    const EXIT_PARTIAL_ERROR = 4;

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
                '/<\s*(script|iframe|object|embed)\b|fromCharCode\s*\(|setTimeout\s*\(|setInterval\s*\(/i',
                '/<\s*form\b[^>]*action\s*=\s*["\'][^"\']*(login|signin|bank|account|paypal|wallet)[^"\']*["\']/i',
		'/\b(eval|assert|base64_decode|system|passthru|proc_open|pcntl_exec|shell_exec|create_function|exec|socket_create|curl_exec|curl_multi_exec|popen|call_user_func|fsockopen|gzuncompress|str_rot13)\s*\(/i',
                '/\$_(GET|POST|REQUEST|COOKIE)\s*\[.*\]\s*\(\$/',
                '/\x75\x6E\x61\x6D\x65\x28\x29\x20\x7B\x20\x7D/i',
                '/file_put_contents\s*\(\s*["\']php:\/\/input["\']\s*,/i', // web shell
                '/preg_replace\s*\(\s*[\'"].*\/e[\'"]\s*,/i', // execute code using modifier `/e`
                '/\b(move_uploaded_file|copy)\s*\(\s*\$_FILES\s*\[\s*[\'"].*[\'"]\s*\]\s*\[\s*[\'"]tmp_name[\'"]\s*\]/i' // bypass file downloads
            ];
        }
    }

    public function scan($path) {
        if (!file_exists($path)) {
            $this->log("Error: Path $path does not exist!", true);
            exit(self::EXIT_RUNTIME_ERROR);
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
                'runtime_errors' => $this->runtimeErrors,
                'infected_files' => array_values($this->infectedFiles)
            ], JSON_PRETTY_PRINT);
        } else {
            $this->log("\nScan complete!");
            $this->log("Total files scanned: " . $this->totalScanned);
            $this->log("Threats found: " . count($this->infectedFiles));
            $this->log("Runtime errors: " . $this->runtimeErrors);
        }

        if (!empty($this->infectedFiles)) {
            foreach ($this->infectedFiles as $file) {
                if (!$this->outputJson) {
                    $this->log(" - $file", true);
                }

                if ($this->quarantinePath) {
                    $this->moveToQuarantine($file);
                }
            }

            exit(self::EXIT_THREATS_FOUND);
        }

        if ($this->runtimeErrors > 0) {
            exit(self::EXIT_PARTIAL_ERROR);
        }

        exit(self::EXIT_CLEAN);
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
            $this->addRuntimeError("Error scanning directory: " . $e->getMessage());
        }
    }

    private function checkFile($file) {
        $this->log("Checking: $file");

        if (!is_file($file)) {
            $this->addRuntimeError("Skipping non-regular file: $file");
            return;
        }

        if (!is_readable($file)) {
            $this->addRuntimeError("Cannot read file: $file");
            return;
        }

        if ($this->isBinaryFile($file)) {
            $this->log("Skipping binary file: $file");
            return;
        }

        $size = @filesize($file);

        if ($size === false) {
            $this->addRuntimeError("Cannot determine file size: $file");
            return;
        }

        if ($size > $this->maxFileSize) {
            $this->processLargeFile($file);
            return;
        }

        $content = @file_get_contents($file);

        if ($content === false) {
            $this->addRuntimeError("Failed to read file: $file");
            return;
        }

        $this->checkContent($content, $file);
    }

    private function processLargeFile($file) {
        $this->log("Processing large file: $file");

        $handle = @fopen($file, 'rb');

        if ($handle === false) {
            $this->addRuntimeError("Failed to open large file: $file");
            return;
        }

        $buffer = '';

        while (!feof($handle)) {
            $chunk = fread($handle, $this->blockSize);

            if ($chunk === false) {
                $this->addRuntimeError("Failed to read chunk from file: $file");
                break;
            }

            if ($chunk === '') {
                break;
            }

            $buffer .= $chunk;
            $this->checkContent($buffer, $file);
            $buffer = substr($buffer, -512);

            if (isset($this->infectedFiles[$file])) {
                break;
            }
        }

        fclose($handle);
    }

    private function checkContent($text, $file) {
        if ($text === false || $text === '') {
            return;
        }

        foreach ($this->virusSignatures as $signature) {
            if (!$this->isValidRegex($signature)) {
                $this->log("Invalid signature skipped: $signature", true);
                continue;
            }

            if (preg_match($signature, $text)) {
                $this->infectedFiles[$file] = $file;
                $this->log("Threat detected in: $file", true);
                return;
            }
        }
    }

    private function isValidRegex($pattern) {
        set_error_handler(function () {});
        $result = preg_match($pattern, '');
        restore_error_handler();

        return $result !== false;
    }

    private function isBinaryFile($file) {
        $maxSignatureLength = 0;

        foreach ($this->binaryFormats as $signature) {
            $length = strlen($signature);

            if ($length > $maxSignatureLength) {
                $maxSignatureLength = $length;
            }
        }

        if ($maxSignatureLength <= 0) {
            return false;
        }

        $header = @file_get_contents($file, false, null, 0, $maxSignatureLength);

        if ($header === false || $header === '') {
            return false;
        }

        foreach ($this->binaryFormats as $signature) {
            if (strpos($header, $signature) === 0) {
                return true;
            }
        }

        return false;
    }

    private function moveToQuarantine($file) {
        if (!is_file($file)) {
            $this->log("Cannot quarantine non-regular file: $file", true);
            return;
        }

        if (!is_readable($file)) {
            $this->log("Cannot quarantine unreadable file: $file", true);
            return;
        }

        if (!is_dir($this->quarantinePath)) {
            if (!mkdir($this->quarantinePath, 0755, true) && !is_dir($this->quarantinePath)) {
                $this->log("Failed to create quarantine directory: {$this->quarantinePath}", true);
                return;
            }
        }

        if (!is_writable($this->quarantinePath)) {
            $this->log("Quarantine directory is not writable: {$this->quarantinePath}", true);
            return;
        }

        $originalPath = realpath($file);
        $hash = hash_file('sha256', $file);

        if ($hash === false) {
            $this->log("Failed to calculate hash for: $file", true);
            return;
        }

        $safeName = preg_replace('/[^a-zA-Z0-9._-]/', '_', basename($file));

        $uniqueName =
            date('Ymd_His') . '_' .
            substr($hash, 0, 16) . '_' .
            $safeName;

        $destination =
            rtrim($this->quarantinePath, DIRECTORY_SEPARATOR) .
            DIRECTORY_SEPARATOR .
            $uniqueName;

        if (!@rename($file, $destination)) {
            $this->log("Failed to move file to quarantine: $file", true);
            return;
        }

        $metadata = [
            'original_path' => $originalPath ?: $file,
            'quarantined_path' => $destination,
            'sha256' => $hash,
            'quarantined_at' => date('c'),
            'original_name' => basename($file),
        ];

        $metadataJson = json_encode(
            $metadata,
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
        );

        if ($metadataJson !== false) {
            @file_put_contents($destination . '.json', $metadataJson);
        }

        $this->log("Moved to quarantine: $destination", true);
    }

    private function addRuntimeError($message) {
        $this->runtimeErrors++;
        $this->log($message, true);
    }

    private function log($message, $isError = false) {
        if ($this->logMode === 'verbose' || $isError) {
            $logMessage = date('[Y-m-d H:i:s] ') . $message . PHP_EOL;

            if ($this->outputJson) {
                fwrite(STDERR, $logMessage);
            } else {
                echo $logMessage;
            }

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
    exit(Antivirus::EXIT_CLI_ERROR);
}

$signaturesFile = $options['signatures-file'] ?? null;
$logMode = $options['log-mode'] ?? 'short';
$logFile = $options['log-file'] ?? null;
$quarantinePath = $options['quarantine'] ?? null;
$outputJson = isset($options['json-report']);

$antivirus = new Antivirus($logMode, $signaturesFile, $logFile, $quarantinePath, $outputJson);
$antivirus->scan(rtrim($options['path'], '/'));
