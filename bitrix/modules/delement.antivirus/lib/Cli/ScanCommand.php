<?php

namespace Delement\Antivirus\Cli;

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

            $documentRoot = $this->resolveDocumentRoot($parsed['options']);
            $_SERVER['DOCUMENT_ROOT'] = $documentRoot;
            $options = $this->buildConfigOptions($parsed['options'], $flags, $documentRoot);
            $config = ScanConfig::fromModuleOptions($options, $documentRoot);
            $this->assertDestructiveActionIsConfirmed($config, $flags);
            $runner = $this->runner ?: new ScanRunService($documentRoot, null, null, $this->moduleRoot);
            $response = $runner->runToCompletion($config, 0);
            $payload = $this->buildPayload($response, $config);
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

        if (isset($cliOptions['exclude']) && is_array($cliOptions['exclude'])) {
            $exclusions = $this->normalizeExclusions($cliOptions['exclude']);
            $baseExclusions = isset($options['exclude_paths']) ? trim((string)$options['exclude_paths']) : '';
            $options['exclude_paths'] = trim($baseExclusions . "\n" . implode("\n", $exclusions));
        }

        $options['scan_path'] = str_replace('#DOCUMENT_ROOT#', $documentRoot, (string)($options['scan_path'] ?? $documentRoot));
        $options['quarantine_path'] = str_replace('#DOCUMENT_ROOT#', $documentRoot, (string)($options['quarantine_path'] ?? ''));

        return $options;
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
            'runtime_errors' => (int)($response['runtime_errors'] ?? 0),
            'report_path' => (string)($response['report_path'] ?? ''),
            'path' => $config->getPath(),
            'scan_profile' => $config->getScanProfile(),
            'profile' => $config->getProfile(),
            'action' => $config->getAction(),
            'dry_run' => $config->isDryRun(),
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
