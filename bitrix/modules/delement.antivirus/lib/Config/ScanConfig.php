<?php

namespace Delement\Antivirus\Config;

class ScanConfig
{
    public const PROFILE_BALANCED = 'balanced';
    public const PROFILE_STRICT = 'strict';
    public const PROFILE_PARANOID = 'paranoid';

    public const ACTION_REPORT = 'report';
    public const ACTION_QUARANTINE = 'quarantine';
    public const ACTION_DELETE = 'delete';

    private const DEFAULT_EXTENSIONS = [
        'php',
        'js',
        'phtml',
        'phtm',
        'cgi',
        'pl',
        'o',
        'so',
        'py',
        'sh',
        'php3',
        'php4',
        'php5',
        'php6',
        'php7',
        'pht',
        'shtml',
        'susp',
        'suspected',
        'infected',
        'vir',
        'html',
        'htm',
        'tpl',
        'inc',
        'css',
        'txt',
        'sql',
        'svg',
        'htaccess',
    ];

    private const THRESHOLDS = [
        self::PROFILE_BALANCED => ['suspicious' => 4, 'malicious' => 8],
        self::PROFILE_STRICT => ['suspicious' => 3, 'malicious' => 6],
        self::PROFILE_PARANOID => ['suspicious' => 2, 'malicious' => 5],
    ];

    private $path;
    private $profile;
    private $action;
    private $dryRun;
    private $quarantinePath;
    private $signaturesPath;
    private $excludePaths;
    private $batchSize;
    private $maxFileSizeBytes;
    private $extensions;
    private $documentRoot;

    public function __construct(array $options = [])
    {
        $this->documentRoot = isset($options['document_root']) ? (string)$options['document_root'] : $this->detectDocumentRoot();
        $this->path = $this->expandDocumentRoot(isset($options['path']) ? (string)$options['path'] : $this->documentRoot);
        $this->profile = $this->normalizeProfile(isset($options['profile']) ? (string)$options['profile'] : self::PROFILE_BALANCED);
        $this->action = $this->normalizeAction(isset($options['action']) ? (string)$options['action'] : self::ACTION_REPORT);
        $this->dryRun = $this->normalizeBool(isset($options['dry_run']) ? $options['dry_run'] : true);
        $this->quarantinePath = $this->expandDocumentRoot(isset($options['quarantine_path']) ? (string)$options['quarantine_path'] : '');
        $this->signaturesPath = $this->normalizeOptionalPath(isset($options['signatures_path']) ? (string)$options['signatures_path'] : '');
        $this->excludePaths = $this->normalizeLines(isset($options['exclude_paths']) ? $options['exclude_paths'] : []);
        $this->batchSize = $this->normalizeInt(isset($options['batch_size']) ? $options['batch_size'] : 50, 1, 1000);
        $this->maxFileSizeBytes = isset($options['max_file_size_bytes'])
            ? $this->normalizeInt($options['max_file_size_bytes'], 1, 1024 * 1024 * 1024)
            : $this->normalizeMaxFileSize(isset($options['max_file_size_mb']) ? $options['max_file_size_mb'] : 100);
        $this->extensions = $this->normalizeExtensions(isset($options['extensions']) ? $options['extensions'] : self::DEFAULT_EXTENSIONS);
    }

    public static function fromModuleOptions(array $options, $documentRoot = null): self
    {
        return new self([
            'document_root' => $documentRoot,
            'path' => isset($options['scan_path']) ? $options['scan_path'] : null,
            'profile' => isset($options['profile']) ? $options['profile'] : null,
            'action' => isset($options['action']) ? $options['action'] : null,
            'dry_run' => isset($options['dry_run']) ? $options['dry_run'] : null,
            'quarantine_path' => isset($options['quarantine_path']) ? $options['quarantine_path'] : null,
            'signatures_path' => isset($options['signatures_path']) ? $options['signatures_path'] : null,
            'exclude_paths' => isset($options['exclude_paths']) ? $options['exclude_paths'] : [],
            'batch_size' => isset($options['batch_size']) ? $options['batch_size'] : null,
            'max_file_size_mb' => isset($options['max_file_size_mb']) ? $options['max_file_size_mb'] : null,
        ]);
    }

    public static function fromArray(array $options): self
    {
        return new self($options);
    }

    public function getPath(): string
    {
        return $this->path;
    }

    public function getProfile(): string
    {
        return $this->profile;
    }

    public function getAction(): string
    {
        return $this->action;
    }

    public function isDryRun(): bool
    {
        return $this->dryRun;
    }

    public function getQuarantinePath(): string
    {
        return $this->quarantinePath;
    }

    public function getSignaturesPath(): string
    {
        return $this->signaturesPath;
    }

    public function getExcludePaths(): array
    {
        return $this->excludePaths;
    }

    public function getBatchSize(): int
    {
        return $this->batchSize;
    }

    public function getMaxFileSizeBytes(): int
    {
        return $this->maxFileSizeBytes;
    }

    public function getExtensions(): array
    {
        return $this->extensions;
    }

    public function getDocumentRoot(): string
    {
        return $this->documentRoot;
    }

    public function getThresholds(): array
    {
        return self::THRESHOLDS[$this->profile];
    }

    public function toArray(): array
    {
        return [
            'document_root' => $this->documentRoot,
            'path' => $this->path,
            'profile' => $this->profile,
            'action' => $this->action,
            'dry_run' => $this->dryRun,
            'quarantine_path' => $this->quarantinePath,
            'signatures_path' => $this->signaturesPath,
            'exclude_paths' => $this->excludePaths,
            'batch_size' => $this->batchSize,
            'max_file_size_bytes' => $this->maxFileSizeBytes,
            'extensions' => $this->extensions,
        ];
    }

    private function detectDocumentRoot(): string
    {
        if (!empty($_SERVER['DOCUMENT_ROOT'])) {
            return rtrim((string)$_SERVER['DOCUMENT_ROOT'], '/\\');
        }

        return '';
    }

    private function expandDocumentRoot(string $value): string
    {
        if ($this->documentRoot !== '') {
            $value = str_replace('#DOCUMENT_ROOT#', $this->documentRoot, $value);
        }

        return rtrim($value, '/\\');
    }

    private function normalizeProfile(string $profile): string
    {
        return isset(self::THRESHOLDS[$profile]) ? $profile : self::PROFILE_BALANCED;
    }

    private function normalizeAction(string $action): string
    {
        $allowed = [self::ACTION_REPORT, self::ACTION_QUARANTINE, self::ACTION_DELETE];

        return in_array($action, $allowed, true) ? $action : self::ACTION_REPORT;
    }

    private function normalizeBool($value): bool
    {
        return $value === true || $value === 'Y' || $value === '1' || $value === 1;
    }

    private function normalizeOptionalPath(string $path): string
    {
        $path = trim($path);

        if ($path === '') {
            return '';
        }

        return $this->expandDocumentRoot($path);
    }

    private function normalizeInt($value, int $min, int $max): int
    {
        $value = (int)$value;

        if ($value < $min) {
            return $min;
        }

        if ($value > $max) {
            return $max;
        }

        return $value;
    }

    private function normalizeMaxFileSize($value): int
    {
        $megabytes = $this->normalizeInt($value, 1, 1024);

        return $megabytes * 1024 * 1024;
    }

    private function normalizeLines($value): array
    {
        if (is_array($value)) {
            $lines = $value;
        } else {
            $lines = preg_split('/\r\n|\r|\n/', (string)$value);
        }

        $normalized = [];
        $seen = [];

        foreach ($lines as $line) {
            $line = trim((string)$line);

            if ($line === '') {
                continue;
            }

            $line = $this->normalizePath($this->expandDocumentRoot($line));

            if (!isset($seen[$line])) {
                $normalized[] = $line;
                $seen[$line] = true;
            }
        }

        return $normalized;
    }

    private function normalizeExtensions($value): array
    {
        $extensions = is_array($value) ? $value : explode(',', (string)$value);
        $normalized = [];

        foreach ($extensions as $extension) {
            $extension = strtolower(trim((string)$extension));
            $extension = ltrim($extension, '.');

            if ($extension !== '') {
                $normalized[$extension] = $extension;
            }
        }

        return array_values($normalized);
    }

    private function normalizePath(string $path): string
    {
        return str_replace('\\', '/', rtrim($path, '/\\'));
    }
}
