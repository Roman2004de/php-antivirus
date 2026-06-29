<?php

namespace Delement\Antivirus\Config;

class ScanConfig
{
    public const PROFILE_BALANCED = 'balanced';
    public const PROFILE_STRICT = 'strict';
    public const PROFILE_PARANOID = 'paranoid';

    public const SCAN_PROFILE_QUICK = 'quick';
    public const SCAN_PROFILE_STANDARD = 'standard';
    public const SCAN_PROFILE_DEEP = 'deep';

    public const ACTION_REPORT = 'report';
    public const ACTION_QUARANTINE = 'quarantine';
    public const ACTION_DELETE = 'delete';

    private const STANDARD_EXTENSIONS = [
        'php',
        'js',
        'phtml',
        'module',
        'include',
        'phtm',
        'cgi',
        'pl',
        'py',
        'sh',
        'php3',
        'php4',
        'php5',
        'php6',
        'php7',
        'php8',
        'pht',
        'shtml',
        'html',
        'htm',
        'tpl',
        'inc',
        'css',
    ];

    private const DEEP_EXTENSIONS = [
        'php',
        'js',
        'phtml',
        'module',
        'include',
        'phtm',
        'cgi',
        'pl',
        'py',
        'sh',
        'php3',
        'php4',
        'php5',
        'php6',
        'php7',
        'php8',
        'pht',
        'shtml',
        'html',
        'htm',
        'tpl',
        'inc',
        'css',
        'txt',
        'sql',
        'svg',
        'htaccess',
        'susp',
        'suspected',
        'infected',
        'vir',
        'o',
        'so',
    ];

    private const THRESHOLDS = [
        self::PROFILE_BALANCED => ['suspicious' => 4, 'malicious' => 8],
        self::PROFILE_STRICT => ['suspicious' => 3, 'malicious' => 6],
        self::PROFILE_PARANOID => ['suspicious' => 2, 'malicious' => 5],
    ];

    private $path;
    private $scanProfile;
    private $profile;
    private $action;
    private $dryRun;
    private $quarantinePath;
    private $signaturesPath;
    private $excludePaths;
    private $batchSize;
    private $maxFileSizeBytes;
    private $enableCommonStringsPrefilter;
    private $enableNormalizedHash;
    private $normalizedHashMaxFileSizeBytes;
    private $enableAstAnalysis;
    private $astMaxFileSize;
    private $disableEntropyAnalyzer;
    private $enableEntropyAnalyzer;
    private $enableEntropyInDeepProfile;
    private $entropyMinLength;
    private $entropyThreshold;
    private $entropyContextWindow;
    private $disableUrlAnalyzer;
    private $enableUrlAnalyzer;
    private $suspiciousDomainsPath;
    private $extensions;
    private $documentRoot;

    public function __construct(array $options = [])
    {
        $this->documentRoot = isset($options['document_root']) ? (string)$options['document_root'] : $this->detectDocumentRoot();
        $this->path = $this->expandDocumentRoot(isset($options['path']) ? (string)$options['path'] : $this->documentRoot);
        $this->scanProfile = $this->normalizeScanProfile(isset($options['scan_profile']) ? (string)$options['scan_profile'] : self::SCAN_PROFILE_STANDARD);
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
        $this->enableCommonStringsPrefilter = $this->normalizeBool(isset($options['enable_common_strings_prefilter']) ? $options['enable_common_strings_prefilter'] : true);
        $this->enableNormalizedHash = $this->normalizeBool(isset($options['enable_normalized_hash']) ? $options['enable_normalized_hash'] : true);
        $this->normalizedHashMaxFileSizeBytes = isset($options['normalized_hash_max_file_size_bytes'])
            ? $this->normalizeInt($options['normalized_hash_max_file_size_bytes'], 1, 1024 * 1024 * 1024)
            : $this->normalizeMaxFileSize(isset($options['normalized_hash_max_file_size_mb']) ? $options['normalized_hash_max_file_size_mb'] : 5);
        $this->enableAstAnalysis = $this->normalizeBool(isset($options['enable_ast_analysis']) ? $options['enable_ast_analysis'] : true);
        $this->astMaxFileSize = $this->normalizeInt(isset($options['ast_max_file_size']) ? $options['ast_max_file_size'] : 1048576, 1, 100 * 1024 * 1024);
        $this->disableEntropyAnalyzer = $this->normalizeBool(isset($options['disable_entropy_analyzer']) ? $options['disable_entropy_analyzer'] : false);
        $this->enableEntropyAnalyzer = $this->normalizeBool(isset($options['enable_entropy_analyzer']) ? $options['enable_entropy_analyzer'] : false);
        $this->enableEntropyInDeepProfile = $this->normalizeBool(isset($options['enable_entropy_in_deep_profile']) ? $options['enable_entropy_in_deep_profile'] : true);
        $this->entropyMinLength = $this->normalizeInt(isset($options['entropy_min_length']) ? $options['entropy_min_length'] : 200, 20, 100000);
        $this->entropyThreshold = $this->normalizeFloat(isset($options['entropy_threshold']) ? $options['entropy_threshold'] : 4.7, 0.1, 8.0);
        $this->entropyContextWindow = $this->normalizeInt(isset($options['entropy_context_window']) ? $options['entropy_context_window'] : 300, 0, 10000);
        $this->disableUrlAnalyzer = $this->normalizeBool(isset($options['disable_url_analyzer']) ? $options['disable_url_analyzer'] : false);
        $this->enableUrlAnalyzer = $this->normalizeBool(isset($options['enable_url_analyzer']) ? $options['enable_url_analyzer'] : true);
        $this->suspiciousDomainsPath = $this->normalizeOptionalPath(isset($options['suspicious_domains_path']) ? (string)$options['suspicious_domains_path'] : '');
        $this->extensions = $this->normalizeExtensions(isset($options['extensions']) ? $options['extensions'] : $this->defaultExtensionsForScanProfile($this->scanProfile));
    }

    public static function fromModuleOptions(array $options, $documentRoot = null): self
    {
        return new self([
            'document_root' => $documentRoot,
            'path' => isset($options['scan_path']) ? $options['scan_path'] : null,
            'scan_profile' => isset($options['scan_profile']) ? $options['scan_profile'] : null,
            'profile' => isset($options['profile']) ? $options['profile'] : null,
            'action' => isset($options['action']) ? $options['action'] : null,
            'dry_run' => isset($options['dry_run']) ? $options['dry_run'] : null,
            'quarantine_path' => isset($options['quarantine_path']) ? $options['quarantine_path'] : null,
            'signatures_path' => isset($options['signatures_path']) ? $options['signatures_path'] : null,
            'exclude_paths' => isset($options['exclude_paths']) ? $options['exclude_paths'] : [],
            'batch_size' => isset($options['batch_size']) ? $options['batch_size'] : null,
            'max_file_size_mb' => isset($options['max_file_size_mb']) ? $options['max_file_size_mb'] : null,
            'enable_common_strings_prefilter' => isset($options['enable_common_strings_prefilter']) ? $options['enable_common_strings_prefilter'] : null,
            'enable_normalized_hash' => isset($options['enable_normalized_hash']) ? $options['enable_normalized_hash'] : null,
            'normalized_hash_max_file_size_mb' => isset($options['normalized_hash_max_file_size_mb']) ? $options['normalized_hash_max_file_size_mb'] : null,
            'enable_ast_analysis' => isset($options['enable_ast_analysis']) ? $options['enable_ast_analysis'] : null,
            'ast_max_file_size' => isset($options['ast_max_file_size']) ? $options['ast_max_file_size'] : null,
            'disable_entropy_analyzer' => isset($options['disable_entropy_analyzer']) ? $options['disable_entropy_analyzer'] : null,
            'enable_entropy_analyzer' => isset($options['enable_entropy_analyzer']) ? $options['enable_entropy_analyzer'] : null,
            'enable_entropy_in_deep_profile' => isset($options['enable_entropy_in_deep_profile']) ? $options['enable_entropy_in_deep_profile'] : null,
            'entropy_min_length' => isset($options['entropy_min_length']) ? $options['entropy_min_length'] : null,
            'entropy_threshold' => isset($options['entropy_threshold']) ? $options['entropy_threshold'] : null,
            'entropy_context_window' => isset($options['entropy_context_window']) ? $options['entropy_context_window'] : null,
            'disable_url_analyzer' => isset($options['disable_url_analyzer']) ? $options['disable_url_analyzer'] : null,
            'enable_url_analyzer' => isset($options['enable_url_analyzer']) ? $options['enable_url_analyzer'] : null,
            'suspicious_domains_path' => isset($options['suspicious_domains_path']) ? $options['suspicious_domains_path'] : null,
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

    public function getScanProfile(): string
    {
        return $this->scanProfile;
    }

    public function getScanPaths(): array
    {
        if ($this->scanProfile !== self::SCAN_PROFILE_QUICK) {
            return $this->uniquePaths([$this->path]);
        }

        $root = $this->documentRoot !== '' ? $this->documentRoot : $this->path;
        $root = rtrim($root, '/\\');

        if ($root === '') {
            return $this->uniquePaths([$this->path]);
        }

        return $this->uniquePaths([
            $root . '/upload',
            $root . '/bitrix/php_interface',
            $root . '/local/php_interface',
            $root . '/local/modules',
        ]);
    }

    public function ignoresMissingScanPaths(): bool
    {
        return $this->scanProfile === self::SCAN_PROFILE_QUICK;
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

    public function isAstAnalysisEnabled(): bool
    {
        return $this->enableAstAnalysis;
    }

    public function isCommonStringsPrefilterEnabled(): bool
    {
        return $this->enableCommonStringsPrefilter;
    }

    public function isNormalizedHashEnabled(): bool
    {
        return $this->enableNormalizedHash;
    }

    public function getNormalizedHashMaxFileSizeBytes(): int
    {
        return $this->normalizedHashMaxFileSizeBytes;
    }

    public function getAstMaxFileSize(): int
    {
        return $this->astMaxFileSize;
    }

    public function isEntropyAnalyzerEnabled(): bool
    {
        if ($this->disableEntropyAnalyzer) {
            return false;
        }

        if ($this->enableEntropyAnalyzer) {
            return true;
        }

        if ($this->enableEntropyInDeepProfile && $this->scanProfile === self::SCAN_PROFILE_DEEP) {
            return true;
        }

        return in_array($this->profile, [self::PROFILE_STRICT, self::PROFILE_PARANOID], true);
    }

    public function isEntropyAnalyzerExplicitlyEnabled(): bool
    {
        return $this->enableEntropyAnalyzer;
    }

    public function isEntropyAnalyzerExplicitlyDisabled(): bool
    {
        return $this->disableEntropyAnalyzer;
    }

    public function isEntropyInDeepProfileEnabled(): bool
    {
        return $this->enableEntropyInDeepProfile;
    }

    public function getEntropyMinLength(): int
    {
        return $this->entropyMinLength;
    }

    public function getEntropyThreshold(): float
    {
        return $this->entropyThreshold;
    }

    public function getEntropyContextWindow(): int
    {
        return $this->entropyContextWindow;
    }

    public function isUrlAnalyzerEnabled(): bool
    {
        if ($this->disableUrlAnalyzer) {
            return false;
        }

        return $this->enableUrlAnalyzer;
    }

    public function isUrlAnalyzerExplicitlyDisabled(): bool
    {
        return $this->disableUrlAnalyzer;
    }

    public function getSuspiciousDomainsPath(): string
    {
        return $this->suspiciousDomainsPath;
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
            'scan_profile' => $this->scanProfile,
            'scan_paths' => $this->getScanPaths(),
            'profile' => $this->profile,
            'action' => $this->action,
            'dry_run' => $this->dryRun,
            'quarantine_path' => $this->quarantinePath,
            'signatures_path' => $this->signaturesPath,
            'exclude_paths' => $this->excludePaths,
            'batch_size' => $this->batchSize,
            'max_file_size_bytes' => $this->maxFileSizeBytes,
            'enable_common_strings_prefilter' => $this->enableCommonStringsPrefilter,
            'enable_normalized_hash' => $this->enableNormalizedHash,
            'normalized_hash_max_file_size_bytes' => $this->normalizedHashMaxFileSizeBytes,
            'enable_ast_analysis' => $this->enableAstAnalysis,
            'ast_max_file_size' => $this->astMaxFileSize,
            'disable_entropy_analyzer' => $this->disableEntropyAnalyzer,
            'enable_entropy_analyzer' => $this->enableEntropyAnalyzer,
            'enable_entropy_in_deep_profile' => $this->enableEntropyInDeepProfile,
            'entropy_effective_enabled' => $this->isEntropyAnalyzerEnabled(),
            'entropy_min_length' => $this->entropyMinLength,
            'entropy_threshold' => $this->entropyThreshold,
            'entropy_context_window' => $this->entropyContextWindow,
            'disable_url_analyzer' => $this->disableUrlAnalyzer,
            'enable_url_analyzer' => $this->enableUrlAnalyzer,
            'url_effective_enabled' => $this->isUrlAnalyzerEnabled(),
            'suspicious_domains_path' => $this->suspiciousDomainsPath,
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

    private function normalizeScanProfile(string $scanProfile): string
    {
        $allowed = [self::SCAN_PROFILE_QUICK, self::SCAN_PROFILE_STANDARD, self::SCAN_PROFILE_DEEP];

        return in_array($scanProfile, $allowed, true) ? $scanProfile : self::SCAN_PROFILE_STANDARD;
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

    private function normalizeFloat($value, float $min, float $max): float
    {
        $value = (float)str_replace(',', '.', (string)$value);

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

    private function defaultExtensionsForScanProfile(string $scanProfile): array
    {
        if ($scanProfile === self::SCAN_PROFILE_DEEP) {
            return self::DEEP_EXTENSIONS;
        }

        return self::STANDARD_EXTENSIONS;
    }

    private function uniquePaths(array $paths): array
    {
        $normalizedPaths = [];
        $seen = [];

        foreach ($paths as $path) {
            $path = $this->normalizePath((string)$path);

            if ($path === '') {
                continue;
            }

            $key = strtolower($path);

            if (!isset($seen[$key])) {
                $normalizedPaths[] = $path;
                $seen[$key] = true;
            }
        }

        return $normalizedPaths;
    }

    private function normalizePath(string $path): string
    {
        return str_replace('\\', '/', rtrim($path, '/\\'));
    }
}
