<?php

namespace Delement\Antivirus\Cli;

use Delement\Antivirus\Baseline\BaselineManager;
use Delement\Antivirus\Baseline\BaselineStorage;
use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\Scanner\ScanRunService;
use Delement\Antivirus\Support\ModuleVersion;
use InvalidArgumentException;
use RuntimeException;
use Throwable;

class ScanCommand
{
    public const EXIT_OK = 0;
    public const EXIT_FINDINGS = 1;
    public const EXIT_USAGE = 2;
    public const EXIT_RUNTIME_ERROR = 3;
    public const EXIT_SCAN_CONFLICT = 4;

    private const MODULE_ID = 'delement.antivirus';

    private $moduleId;
    private $documentRoot;
    private $moduleRoot;
    private $moduleOptions;
    private $runner;
    private $parser;

    public function __construct(
        string $documentRoot,
        array $moduleOptions = [],
        string $moduleRoot = null,
        ScanRunService $runner = null,
        ArgvParser $parser = null,
        string $moduleId = self::MODULE_ID
    ) {
        $this->moduleId = $moduleId;
        $this->documentRoot = rtrim($documentRoot, '/\\');
        $this->moduleRoot = $moduleRoot ?: dirname(__DIR__, 2);
        $this->moduleOptions = $moduleOptions;
        $this->runner = $runner;
        $this->parser = $parser ?: new ArgvParser();
    }

    public function execute(array $argv): array
    {
        try {
            $parsed = $this->parser->parse($argv);
            $flags = $parsed['flags'];

            if (!empty($flags['help'])) {
                return $this->result(self::EXIT_OK, $this->helpText() . PHP_EOL, '');
            }

            if (!empty($flags['version'])) {
                return $this->result(self::EXIT_OK, ModuleVersion::version($this->moduleRoot) . PHP_EOL, '');
            }

            if ($this->isPanelicaImportRequest($parsed['options'], $flags)) {
                return (new PanelicaImportCommand($this->moduleRoot))->execute($parsed['options'], !empty($flags['json']), $flags);
            }

            $documentRoot = $this->resolveDocumentRoot($parsed['options']);
            $_SERVER['DOCUMENT_ROOT'] = $documentRoot;
            $options = $this->buildConfigOptions($parsed['options'], $flags, $documentRoot);
            $config = ScanConfig::fromModuleOptions($options, $documentRoot);

            if ($this->isBaselineRequest($flags)) {
                return $this->runBaselineCommand($flags, $config, !empty($flags['json']));
            }

            $this->assertDestructiveActionIsConfirmed($config, $flags);
            $runner = $this->runner ?: new ScanRunService($documentRoot, null, null, $this->moduleRoot);
            $response = $runner->runToCompletion($config, 0);
            $payload = $this->buildPayload($response, $config);
            $this->exportReportIfRequested($payload, $parsed['options']);
            $exitCode = $this->exitCode($payload);

            return $this->result(
                $exitCode,
                !empty($flags['json']) ? $this->json($payload) . PHP_EOL : $this->humanSummary($payload),
                ''
            );
        } catch (InvalidArgumentException $exception) {
            return $this->errorResult(self::EXIT_USAGE, $exception->getMessage(), !empty($flags['json'] ?? false));
        } catch (RuntimeException $exception) {
            $code = $exception->getMessage() === 'scan_already_running' ? self::EXIT_SCAN_CONFLICT : self::EXIT_RUNTIME_ERROR;

            return $this->errorResult($code, $exception->getMessage(), !empty($flags['json'] ?? false));
        } catch (Throwable $exception) {
            return $this->errorResult(self::EXIT_RUNTIME_ERROR, 'internal_error', !empty($flags['json'] ?? false));
        }
    }

    private function buildConfigOptions(array $cliOptions, array $flags, string $documentRoot): array
    {
        $options = $this->baseOptions();

        if (isset($cliOptions['path'])) {
            $options['scan_path'] = (string)$cliOptions['path'];
        }

        if (isset($cliOptions['scan-profile'])) {
            $this->assertAllowedValue('scan-profile', (string)$cliOptions['scan-profile'], [
                ScanConfig::SCAN_PROFILE_QUICK,
                ScanConfig::SCAN_PROFILE_STANDARD,
                ScanConfig::SCAN_PROFILE_DEEP,
            ]);
            $options['scan_profile'] = (string)$cliOptions['scan-profile'];
        }

        if (isset($cliOptions['profile'])) {
            $this->assertAllowedValue('profile', (string)$cliOptions['profile'], [
                ScanConfig::PROFILE_BALANCED,
                ScanConfig::PROFILE_STRICT,
                ScanConfig::PROFILE_PARANOID,
            ]);
            $options['profile'] = (string)$cliOptions['profile'];
        }

        if (isset($cliOptions['action'])) {
            $this->assertAllowedValue('action', (string)$cliOptions['action'], [
                ScanConfig::ACTION_REPORT,
                ScanConfig::ACTION_QUARANTINE,
                ScanConfig::ACTION_DELETE,
            ]);
            $options['action'] = (string)$cliOptions['action'];
        }

        if (!empty($flags['dry-run']) && !empty($flags['no-dry-run'])) {
            throw new InvalidArgumentException('cli_dry_run_flags_conflict');
        }

        if (!empty($flags['dry-run'])) {
            $options['dry_run'] = 'Y';
        } elseif (!empty($flags['no-dry-run'])) {
            $options['dry_run'] = 'N';
        }

        if (!empty($flags['enable-ast']) && !empty($flags['disable-ast'])) {
            throw new InvalidArgumentException('cli_ast_flags_conflict');
        }

        if (!empty($flags['enable-ast'])) {
            $options['enable_ast_analysis'] = 'Y';
        } elseif (!empty($flags['disable-ast'])) {
            $options['enable_ast_analysis'] = 'N';
        }

        if (!empty($flags['enable-prefilter']) && !empty($flags['disable-prefilter'])) {
            throw new InvalidArgumentException('cli_prefilter_flags_conflict');
        }

        if (!empty($flags['enable-prefilter'])) {
            $options['enable_common_strings_prefilter'] = 'Y';
        } elseif (!empty($flags['disable-prefilter'])) {
            $options['enable_common_strings_prefilter'] = 'N';
        }

        if (!empty($flags['enable-normalized-hash']) && !empty($flags['disable-normalized-hash'])) {
            throw new InvalidArgumentException('cli_normalized_hash_flags_conflict');
        }

        if (!empty($flags['enable-normalized-hash'])) {
            $options['enable_normalized_hash'] = 'Y';
        } elseif (!empty($flags['disable-normalized-hash'])) {
            $options['enable_normalized_hash'] = 'N';
        }

        if (!empty($flags['enable-entropy']) && !empty($flags['disable-entropy'])) {
            throw new InvalidArgumentException('cli_entropy_flags_conflict');
        }

        if (!empty($flags['enable-entropy'])) {
            $options['disable_entropy_analyzer'] = 'N';
            $options['enable_entropy_analyzer'] = 'Y';
        } elseif (!empty($flags['disable-entropy'])) {
            $options['disable_entropy_analyzer'] = 'Y';
            $options['enable_entropy_analyzer'] = 'N';
            $options['enable_entropy_in_deep_profile'] = 'N';
        }

        if (!empty($flags['enable-url-analyzer']) && !empty($flags['disable-url-analyzer'])) {
            throw new InvalidArgumentException('cli_url_analyzer_flags_conflict');
        }

        if (!empty($flags['enable-url-analyzer'])) {
            $options['disable_url_analyzer'] = 'N';
            $options['enable_url_analyzer'] = 'Y';
        } elseif (!empty($flags['disable-url-analyzer'])) {
            $options['disable_url_analyzer'] = 'Y';
            $options['enable_url_analyzer'] = 'N';
        }

        if (!empty($flags['enable-hash-db']) && !empty($flags['disable-hash-db'])) {
            throw new InvalidArgumentException('cli_hash_db_flags_conflict');
        }

        if (!empty($flags['enable-hash-db'])) {
            $options['disable_hash_db'] = 'N';
            $options['enable_hash_db'] = 'Y';
        } elseif (!empty($flags['disable-hash-db'])) {
            $options['disable_hash_db'] = 'Y';
            $options['enable_hash_db'] = 'N';
        }

        if (isset($cliOptions['quarantine-path'])) {
            $options['quarantine_path'] = (string)$cliOptions['quarantine-path'];
        }

        if (isset($cliOptions['signatures'])) {
            $options['signatures_path'] = (string)$cliOptions['signatures'];
        }

        if (isset($cliOptions['batch-size'])) {
            $this->assertIntegerRange('batch-size', (string)$cliOptions['batch-size'], 1, 1000);
            $options['batch_size'] = (string)$cliOptions['batch-size'];
        }

        if (isset($cliOptions['max-file-size-mb'])) {
            $this->assertIntegerRange('max-file-size-mb', (string)$cliOptions['max-file-size-mb'], 1, 1024);
            $options['max_file_size_mb'] = (string)$cliOptions['max-file-size-mb'];
        }

        if (isset($cliOptions['normalized-hash-max-file-size-mb'])) {
            $this->assertIntegerRange('normalized-hash-max-file-size-mb', (string)$cliOptions['normalized-hash-max-file-size-mb'], 1, 1024);
            $options['normalized_hash_max_file_size_mb'] = (string)$cliOptions['normalized-hash-max-file-size-mb'];
        }

        if (isset($cliOptions['ast-max-file-size'])) {
            $this->assertIntegerRange('ast-max-file-size', (string)$cliOptions['ast-max-file-size'], 1, 104857600);
            $options['ast_max_file_size'] = (string)$cliOptions['ast-max-file-size'];
        }

        if (isset($cliOptions['entropy-threshold'])) {
            $this->assertFloatRange('entropy-threshold', (string)$cliOptions['entropy-threshold'], 0.1, 8.0);
            $options['entropy_threshold'] = (string)$cliOptions['entropy-threshold'];
        }

        if (isset($cliOptions['entropy-min-length'])) {
            $this->assertIntegerRange('entropy-min-length', (string)$cliOptions['entropy-min-length'], 20, 100000);
            $options['entropy_min_length'] = (string)$cliOptions['entropy-min-length'];
        }

        if (isset($cliOptions['suspicious-domains'])) {
            $options['suspicious_domains_path'] = (string)$cliOptions['suspicious-domains'];
        }

        if (isset($cliOptions['malware-hashes'])) {
            $options['malware_hashes_path'] = (string)$cliOptions['malware-hashes'];
        }

        if (isset($cliOptions['malware-hash-prefixes'])) {
            $options['malware_hash_prefixes_path'] = (string)$cliOptions['malware-hash-prefixes'];
        }

        if (isset($cliOptions['bitrix-db'])) {
            $options['enable_bitrix_db_scan'] = $this->normalizeCliBoolOption('bitrix-db', (string)$cliOptions['bitrix-db']);
        }

        if (isset($cliOptions['scan-agents'])) {
            $options['scan_agents'] = $this->normalizeCliBoolOption('scan-agents', (string)$cliOptions['scan-agents']);
        }

        if (isset($cliOptions['scan-events'])) {
            $options['scan_event_handlers'] = $this->normalizeCliBoolOption('scan-events', (string)$cliOptions['scan-events']);
        }

        if (isset($cliOptions['resolve-event-code'])) {
            $options['resolve_event_handler_code'] = $this->normalizeCliBoolOption('resolve-event-code', (string)$cliOptions['resolve-event-code']);
        }

        if (isset($cliOptions['exclude']) && is_array($cliOptions['exclude'])) {
            $exclusions = $this->normalizeExclusions($cliOptions['exclude']);
            $baseExclusions = isset($options['exclude_paths']) ? trim((string)$options['exclude_paths']) : '';
            $options['exclude_paths'] = trim($baseExclusions . "\n" . implode("\n", $exclusions));
        }

        $options['scan_path'] = str_replace('#DOCUMENT_ROOT#', $documentRoot, (string)($options['scan_path'] ?? $documentRoot));
        $options['quarantine_path'] = str_replace('#DOCUMENT_ROOT#', $documentRoot, (string)($options['quarantine_path'] ?? ''));

        return $options;
    }

    private function isPanelicaImportRequest(array $cliOptions, array $flags): bool
    {
        return isset($cliOptions['import-panelica-hashes'])
            || isset($cliOptions['panelica-source'])
            || !empty($flags['download-panelica-hashes']);
    }

    private function isBaselineRequest(array $flags): bool
    {
        return !empty($flags['baseline-create'])
            || !empty($flags['baseline-check'])
            || !empty($flags['baseline-update']);
    }

    private function runBaselineCommand(array $flags, ScanConfig $config, bool $json): array
    {
        $requested = 0;
        $requested += !empty($flags['baseline-create']) ? 1 : 0;
        $requested += !empty($flags['baseline-check']) ? 1 : 0;
        $requested += !empty($flags['baseline-update']) ? 1 : 0;

        if ($requested !== 1) {
            throw new InvalidArgumentException('cli_baseline_mode_required');
        }

        if (!empty($flags['baseline-update']) && empty($flags['force'])) {
            throw new InvalidArgumentException('cli_force_required_for_baseline_update');
        }

        $manager = new BaselineManager(new BaselineStorage($this->moduleRoot));

        if (!empty($flags['baseline-create'])) {
            $report = $manager->createBaseline($config);
        } elseif (!empty($flags['baseline-update'])) {
            $report = $manager->updateBaseline($config);
        } else {
            $report = $manager->checkBaseline($config);
        }

        $payload = $this->buildBaselinePayload($report);
        $exitCode = $this->baselineExitCode($payload);

        return $this->result(
            $exitCode,
            $json ? $this->json($payload) . PHP_EOL : $this->baselineHumanSummary($payload),
            ''
        );
    }

    private function baseOptions(): array
    {
        $defaults = $this->loadDefaults();

        return array_merge($defaults, $this->moduleOptions);
    }

    private function loadDefaults(): array
    {
        $path = rtrim($this->moduleRoot, '/\\') . DIRECTORY_SEPARATOR . 'default_option.php';
        $delement_antivirus_default_option = [];

        if (is_file($path)) {
            require $path;
        }

        return is_array($delement_antivirus_default_option) ? $delement_antivirus_default_option : [];
    }

    private function resolveDocumentRoot(array $cliOptions): string
    {
        $documentRoot = isset($cliOptions['document-root']) ? (string)$cliOptions['document-root'] : $this->documentRoot;
        $realDocumentRoot = realpath($documentRoot);

        if ($realDocumentRoot === false || !is_dir($realDocumentRoot)) {
            throw new InvalidArgumentException('document_root_not_found');
        }

        return rtrim($realDocumentRoot, '/\\');
    }

    private function assertDestructiveActionIsConfirmed(ScanConfig $config, array $flags): void
    {
        if ($config->isDryRun()) {
            return;
        }

        if ($config->getAction() === ScanConfig::ACTION_REPORT) {
            return;
        }

        if (empty($flags['force'])) {
            throw new InvalidArgumentException('cli_force_required_for_destructive_action');
        }
    }

    private function assertAllowedValue(string $name, string $value, array $allowed): void
    {
        if (!in_array($value, $allowed, true)) {
            throw new InvalidArgumentException('cli_invalid_' . str_replace('-', '_', $name));
        }
    }

    private function assertIntegerRange(string $name, string $value, int $min, int $max): void
    {
        if (!preg_match('/^\d+$/', $value)) {
            throw new InvalidArgumentException('cli_invalid_' . str_replace('-', '_', $name));
        }

        $number = (int)$value;

        if ($number < $min || $number > $max) {
            throw new InvalidArgumentException('cli_invalid_' . str_replace('-', '_', $name));
        }
    }

    private function assertFloatRange(string $name, string $value, float $min, float $max): void
    {
        if (!preg_match('/^\d+(?:[\.,]\d+)?$/', $value)) {
            throw new InvalidArgumentException('cli_invalid_' . str_replace('-', '_', $name));
        }

        $number = (float)str_replace(',', '.', $value);

        if ($number < $min || $number > $max) {
            throw new InvalidArgumentException('cli_invalid_' . str_replace('-', '_', $name));
        }
    }

    private function normalizeExclusions(array $exclusions): array
    {
        $result = [];

        foreach ($exclusions as $exclusion) {
            $exclusion = trim((string)$exclusion);

            if ($exclusion === '') {
                continue;
            }

            $result[] = $exclusion;
        }

        return $result;
    }

    private function normalizeCliBoolOption(string $name, string $value): string
    {
        $value = strtolower(trim($value));

        if (in_array($value, ['y', 'yes', '1', 'true'], true)) {
            return 'Y';
        }

        if (in_array($value, ['n', 'no', '0', 'false'], true)) {
            return 'N';
        }

        throw new InvalidArgumentException('cli_invalid_' . str_replace('-', '_', $name));
    }

    private function buildPayload(array $response, ScanConfig $config): array
    {
        $success = !empty($response['success']) && !in_array((string)($response['status'] ?? ''), ['failed'], true);

        return [
            'success' => $success,
            'module' => $this->moduleId,
            'version' => ModuleVersion::version($this->moduleRoot),
            'status' => (string)($response['status'] ?? 'unknown'),
            'scan_id' => (string)($response['scan_id'] ?? ''),
            'error' => isset($response['error']) ? (string)$response['error'] : '',
            'processed_files' => (int)($response['processed_files'] ?? 0),
            'total_files_estimated' => (int)($response['total_files_estimated'] ?? 0),
            'files_discovered' => (int)($response['files_discovered'] ?? 0),
            'found_total' => (int)($response['found_total'] ?? 0),
            'informational_findings_total' => (int)($response['informational_findings_total'] ?? 0),
            'bitrix_db_results_total' => (int)($response['bitrix_db_results_total'] ?? 0),
            'runtime_errors' => (int)($response['runtime_errors'] ?? 0),
            'report_path' => (string)($response['report_path'] ?? ''),
            'runtime_report_path' => '',
            'tags' => $this->reportTags((string)($response['report_path'] ?? '')),
            'path' => $config->getPath(),
            'scan_profile' => $config->getScanProfile(),
            'profile' => $config->getProfile(),
            'action' => $config->getAction(),
            'dry_run' => $config->isDryRun(),
            'enable_ast_analysis' => $config->isAstAnalysisEnabled(),
            'enable_common_strings_prefilter' => $config->isCommonStringsPrefilterEnabled(),
            'enable_normalized_hash' => $config->isNormalizedHashEnabled(),
            'normalized_hash_max_file_size_bytes' => $config->getNormalizedHashMaxFileSizeBytes(),
            'enable_entropy_analyzer' => $config->isEntropyAnalyzerEnabled(),
            'entropy_min_length' => $config->getEntropyMinLength(),
            'entropy_threshold' => $config->getEntropyThreshold(),
            'enable_url_analyzer' => $config->isUrlAnalyzerEnabled(),
            'suspicious_domains_path' => $config->getSuspiciousDomainsPath(),
            'enable_hash_db' => $config->isHashDatabaseEnabled(),
            'malware_hashes_path' => $config->getMalwareHashesPath(),
            'malware_hash_prefixes_path' => $config->getMalwareHashPrefixesPath(),
            'malware_hash_prefix_length' => $config->getMalwareHashPrefixLength(),
            'enable_bitrix_db_scan' => $config->isBitrixDbScanEnabled(),
            'scan_agents' => $config->isAgentScanEnabled(),
            'scan_event_handlers' => $config->isEventHandlerScanEnabled(),
            'resolve_event_handler_code' => $config->isEventHandlerCodeResolveEnabled(),
            'ast_max_file_size' => $config->getAstMaxFileSize(),
        ];
    }

    private function buildBaselinePayload(array $report): array
    {
        $summary = isset($report['summary']) && is_array($report['summary']) ? $report['summary'] : [];

        return [
            'success' => true,
            'module' => $this->moduleId,
            'version' => ModuleVersion::version($this->moduleRoot),
            'operation' => (string)($summary['operation'] ?? ''),
            'status' => (string)($summary['status'] ?? 'unknown'),
            'report_id' => (string)($report['report_id'] ?? ''),
            'report_path' => (string)($report['report_path'] ?? ''),
            'path' => (string)($summary['path'] ?? ''),
            'baseline_records' => (int)($summary['baseline_records'] ?? 0),
            'current_files' => (int)($summary['current_files'] ?? 0),
            'changed_files' => (int)($summary['changed_files'] ?? 0),
            'new_files' => (int)($summary['new_files'] ?? 0),
            'modified_files' => (int)($summary['modified_files'] ?? 0),
            'deleted_files' => (int)($summary['deleted_files'] ?? 0),
            'critical_changes' => (int)($summary['critical_changes'] ?? 0),
            'findings_total' => (int)($summary['findings_total'] ?? 0),
            'tags' => isset($summary['tags']) && is_array($summary['tags']) ? $summary['tags'] : [],
            'summary' => $summary,
            'results' => isset($report['results']) && is_array($report['results']) ? $report['results'] : [],
        ];
    }

    private function exitCode(array $payload): int
    {
        if (empty($payload['success']) && ($payload['error'] ?? '') === 'scan_already_running') {
            return self::EXIT_SCAN_CONFLICT;
        }

        if (empty($payload['success']) || (int)($payload['runtime_errors'] ?? 0) > 0) {
            return self::EXIT_RUNTIME_ERROR;
        }

        if ((int)($payload['found_total'] ?? 0) > 0) {
            return self::EXIT_FINDINGS;
        }

        return self::EXIT_OK;
    }

    private function baselineExitCode(array $payload): int
    {
        if (empty($payload['success'])) {
            return self::EXIT_RUNTIME_ERROR;
        }

        if ((int)($payload['changed_files'] ?? 0) > 0 || (int)($payload['findings_total'] ?? 0) > 0) {
            return self::EXIT_FINDINGS;
        }

        return self::EXIT_OK;
    }

    private function reportTags(string $reportPath): array
    {
        if ($reportPath === '' || !is_file($reportPath) || !is_readable($reportPath)) {
            return [];
        }

        $report = json_decode((string)file_get_contents($reportPath), true);

        if (!is_array($report) || !isset($report['summary']['tags']) || !is_array($report['summary']['tags'])) {
            return [];
        }

        $tags = [];
        $seen = [];

        foreach ($report['summary']['tags'] as $tag) {
            $tag = strtolower(trim((string)$tag));

            if ($tag === '' || isset($seen[$tag])) {
                continue;
            }

            $tags[] = $tag;
            $seen[$tag] = true;
        }

        sort($tags, SORT_STRING);

        return $tags;
    }

    private function exportReportIfRequested(array &$payload, array $cliOptions): void
    {
        if (!isset($cliOptions['report'])) {
            return;
        }

        if (empty($payload['success'])) {
            return;
        }

        $sourcePath = (string)($payload['report_path'] ?? '');

        if ($sourcePath === '' || !is_file($sourcePath)) {
            throw new RuntimeException('cli_report_source_not_found');
        }

        $targetPath = $this->normalizeReportPath((string)$cliOptions['report']);
        $targetDirectory = dirname($targetPath);

        if (!is_dir($targetDirectory) && !@mkdir($targetDirectory, 0700, true) && !is_dir($targetDirectory)) {
            throw new RuntimeException('cli_report_directory_create_failed');
        }

        if (!is_writable($targetDirectory)) {
            throw new RuntimeException('cli_report_directory_not_writable');
        }

        if (!@copy($sourcePath, $targetPath)) {
            throw new RuntimeException('cli_report_save_failed');
        }

        @chmod($targetPath, 0600);

        $payload['runtime_report_path'] = $sourcePath;
        $payload['report_path'] = $targetPath;
    }

    private function normalizeReportPath(string $path): string
    {
        $path = trim($path);

        if ($path === '' || strpos($path, "\0") !== false || is_dir($path)) {
            throw new InvalidArgumentException('cli_report_path_invalid');
        }

        if (!$this->isAbsolutePath($path)) {
            $cwd = getcwd();

            if ($cwd === false || $cwd === '') {
                throw new RuntimeException('cli_report_path_resolve_failed');
            }

            $path = rtrim($cwd, '/\\') . DIRECTORY_SEPARATOR . $path;
        }

        return rtrim($path, '/\\');
    }

    private function isAbsolutePath(string $path): bool
    {
        return strpos($path, '/') === 0
            || strpos($path, '\\') === 0
            || preg_match('/^[a-zA-Z]:[\/\\\\]/', $path) === 1;
    }

    private function humanSummary(array $payload): string
    {
        $lines = [
            'delement.antivirus scan',
            'Status: ' . $payload['status'],
            'Scan ID: ' . $payload['scan_id'],
            'Path: ' . $payload['path'],
            'Profile: ' . $payload['scan_profile'] . ' / ' . $payload['profile'],
            'Action: ' . $payload['action'] . ($payload['dry_run'] ? ' (dry-run)' : ''),
            'Processed: ' . $payload['processed_files'] . '/' . $payload['total_files_estimated'],
            'Found: ' . $payload['found_total'],
            'Informational findings: ' . $payload['informational_findings_total'],
            'Bitrix DB results: ' . $payload['bitrix_db_results_total'],
            'Runtime errors: ' . $payload['runtime_errors'],
        ];

        if ($payload['report_path'] !== '') {
            $lines[] = 'Report: ' . $payload['report_path'];
        }

        if ($payload['error'] !== '') {
            $lines[] = 'Error: ' . $payload['error'];
        }

        return implode(PHP_EOL, $lines) . PHP_EOL;
    }

    private function baselineHumanSummary(array $payload): string
    {
        $lines = [
            'delement.antivirus baseline',
            'Operation: ' . $payload['operation'],
            'Status: ' . $payload['status'],
            'Path: ' . $payload['path'],
            'Baseline records: ' . $payload['baseline_records'],
            'Current files: ' . $payload['current_files'],
            'Changed files: ' . $payload['changed_files'],
            'New: ' . $payload['new_files'],
            'Modified: ' . $payload['modified_files'],
            'Deleted: ' . $payload['deleted_files'],
            'Critical changes: ' . $payload['critical_changes'],
        ];

        if ($payload['report_path'] !== '') {
            $lines[] = 'Report: ' . $payload['report_path'];
        }

        return implode(PHP_EOL, $lines) . PHP_EOL;
    }

    private function errorResult(int $exitCode, string $error, bool $json): array
    {
        $payload = [
            'success' => false,
            'module' => $this->moduleId,
            'version' => ModuleVersion::version($this->moduleRoot),
            'error' => $error,
        ];

        if ($json) {
            return $this->result($exitCode, $this->json($payload) . PHP_EOL, '');
        }

        return $this->result($exitCode, '', $error . PHP_EOL);
    }

    private function result(int $exitCode, string $stdout, string $stderr): array
    {
        return [
            'exit_code' => $exitCode,
            'stdout' => $stdout,
            'stderr' => $stderr,
        ];
    }

    private function json(array $payload): string
    {
        $json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        return $json === false ? '{"success":false,"error":"json_encode_failed"}' : $json;
    }

    private function helpText(): string
    {
        return <<<'HELP'
delement.antivirus CLI scanner

Usage:
  php scan.php --path=/home/site/public_html --scan-profile=deep --profile=strict --action=report --dry-run --json

Options:
  --path=PATH              Scan path under DOCUMENT_ROOT. Defaults to module settings.
  --document-root=PATH     Site document root. Defaults to the current Bitrix document root.
  --scan-profile=NAME      quick, standard, deep.
  --profile=NAME           balanced, strict, paranoid.
  --action=NAME            report, quarantine, delete.
  --dry-run                Do not change files; report planned actions only.
  --no-dry-run             Allow filesystem changes for quarantine/delete.
  --force                  Required with --no-dry-run and action quarantine/delete.
  --json                   Print final machine-readable JSON to STDOUT.
  --signatures=PATH        External regex signatures file.
  --report=PATH            Save a copy of the final JSON report to this path.
  --enable-ast             Enable PHP AST analysis.
  --disable-ast            Disable PHP AST analysis.
  --enable-prefilter       Enable common strings regex prefilter.
  --disable-prefilter      Disable common strings regex prefilter.
  --enable-normalized-hash Enable normalized hash calculation.
  --disable-normalized-hash Disable normalized hash calculation.
  --normalized-hash-max-file-size-mb=N
                           Maximum file size for normalized hash, 1..1024 MB.
  --enable-entropy         Enable entropy analyzer for encoded payload strings.
  --disable-entropy        Disable entropy analyzer, including deep/strict auto-enable.
  --entropy-threshold=N    Shannon entropy threshold, 0.1..8.0. Default: 4.7.
  --entropy-min-length=N   Minimum candidate string length, 20..100000. Default: 200.
  --enable-url-analyzer    Enable external URL analyzer.
  --disable-url-analyzer   Disable external URL analyzer.
  --suspicious-domains=PATH
                           JSON file with user/test suspicious domains.
  --enable-hash-db         Enable known malware hash database.
  --disable-hash-db        Disable known malware hash database.
  --malware-hashes=PATH    JSON file with full SHA-256 malware hashes.
  --malware-hash-prefixes=PATH
                           JSON file with SHA-256 hash prefixes.
  --bitrix-db=Y|N          Enable or disable Bitrix database scanners.
  --scan-agents=Y|N        Scan b_agent records when Bitrix DB scanning is enabled.
  --scan-events=Y|N        Scan b_module_to_module event handlers when Bitrix DB scanning is enabled.
  --resolve-event-code=Y|N Resolve event handler code files and scan them. Default: Y.
  --import-panelica-hashes=PATH
                           Import Panelica Malware Signatures hashes from a local repository path.
  --download-panelica-hashes
                           Download Panelica hash sources from the allowlisted URL and import them.
  --panelica-source=PATH   Alias for --import-panelica-hashes.
  --panelica-download-url=URL
                           Panelica source URL. Defaults to https://github.com/Panelica/malware-signatures.
  --panelica-hashes-json=PATH
                           Explicit Panelica json/hashes.json path.
  --panelica-sha256-txt=PATH
                           Explicit Panelica hashes/sha256.txt path.
  --panelica-license=PATH  Explicit Panelica LICENSE path.
  --malware-hashes-output=PATH
                           Output path for imported full SHA-256 hashes.
  --malware-prefixes-output=PATH
                           Output path for imported SHA-256 prefixes.
  --malware-hash-prefix-length=N
                           Prefix length for hash index, 8..12. Default: 8.
  --panelica-source-commit=HASH
                           Optional Panelica source commit/version metadata.
  --baseline-create        Create a user file integrity baseline for --path.
  --baseline-check         Compare --path with the saved user baseline.
  --baseline-update        Replace the saved user baseline for --path. Requires --force.
  --ast-max-file-size=N    Maximum PHP file size for AST analysis, bytes.
  --exclude=PATH           Add excluded path. Can be repeated.
  --batch-size=N           Files per scanner batch, 1..1000.
  --max-file-size-mb=N     Maximum file size, 1..1024 MB.
  --quarantine-path=PATH   Quarantine storage path.
  --help                   Show this help without scanning.
  --version                Print module version from install/version.php.

Exit codes:
  0  Scan finished, no suspicious files found.
  1  Scan finished, suspicious files found.
  2  Invalid arguments or configuration.
  3  Runtime error.
  4  Another scan is already running.
HELP;
    }
}
