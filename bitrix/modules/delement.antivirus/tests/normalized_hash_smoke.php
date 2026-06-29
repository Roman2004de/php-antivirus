<?php

use Delement\Antivirus\Cli\ScanCommand;
use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\Scanner\Scanner;

require_once __DIR__ . '/../lib/Storage/RuntimeDirectory.php';
require_once __DIR__ . '/../lib/Support/ModuleVersion.php';
require_once __DIR__ . '/../lib/Cli/ArgvParser.php';
require_once __DIR__ . '/../lib/Cli/ScanCommand.php';
require_once __DIR__ . '/../lib/Config/ScanConfig.php';
require_once __DIR__ . '/../lib/File/FileTypeDetector.php';
require_once __DIR__ . '/../lib/File/FileReader.php';
require_once __DIR__ . '/../lib/File/FileFilter.php';
require_once __DIR__ . '/../lib/File/FileCollector.php';
require_once __DIR__ . '/../lib/Detection/Severity.php';
require_once __DIR__ . '/../lib/Detection/Verdict.php';
require_once __DIR__ . '/../lib/Detection/Finding.php';
require_once __DIR__ . '/../lib/Detection/SignatureLoader.php';
require_once __DIR__ . '/../lib/Detection/RuleEngine.php';
require_once __DIR__ . '/../lib/Detection/Detector.php';
require_once __DIR__ . '/../lib/Scanner/ScanResult.php';
require_once __DIR__ . '/../lib/Scanner/ScanSummary.php';
require_once __DIR__ . '/../lib/Scanner/Scanner.php';
require_once __DIR__ . '/../lib/Scanner/ScanActionApplier.php';
require_once __DIR__ . '/../lib/Scanner/ScanSessionStore.php';
require_once __DIR__ . '/../lib/Scanner/ScanRunService.php';
require_once __DIR__ . '/../lib/Quarantine/QuarantineManager.php';
require_once __DIR__ . '/../lib/Report/JsonReportWriter.php';
require_once __DIR__ . '/../lib/Report/ReportManager.php';
require_once __DIR__ . '/../lib/Whitelist/WhitelistManager.php';

function delement_antivirus_normalized_hash_remove_tree(string $path): void
{
    if (!is_dir($path)) {
        return;
    }

    $items = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );

    foreach ($items as $item) {
        if ($item->isDir()) {
            @rmdir($item->getPathname());
        } else {
            @unlink($item->getPathname());
        }
    }

    @rmdir($path);
}

function delement_antivirus_normalized_hash_fail(string $message, array $context = []): void
{
    fwrite(STDERR, $message . PHP_EOL);

    if (!empty($context)) {
        fwrite(STDERR, json_encode($context, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    }

    exit(1);
}

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'delement_antivirus_normalized_hash_smoke_' . getmypid();
$documentRoot = $root . DIRECTORY_SEPARATOR . 'site';
$moduleRoot = $root . DIRECTORY_SEPARATOR . 'module';

delement_antivirus_normalized_hash_remove_tree($root);

try {
    if (!mkdir($documentRoot, 0777, true) && !is_dir($documentRoot)) {
        delement_antivirus_normalized_hash_fail('Cannot create document root');
    }

    if (!mkdir($moduleRoot . DIRECTORY_SEPARATOR . 'install', 0777, true) && !is_dir($moduleRoot . DIRECTORY_SEPARATOR . 'install')) {
        delement_antivirus_normalized_hash_fail('Cannot create module root');
    }

    file_put_contents($moduleRoot . DIRECTORY_SEPARATOR . 'install' . DIRECTORY_SEPARATOR . 'version.php', "<?php\n\$arModuleVersion = ['VERSION' => '0.0.4'];\n");

    $formatted = "<?php\n\$value = 1;\necho \$value;\n";
    $compact = "<?php \$value=1; echo\$value;";
    $firstPath = $documentRoot . DIRECTORY_SEPARATOR . 'formatted.php';
    $secondPath = $documentRoot . DIRECTORY_SEPARATOR . 'compact.php';
    $largePath = $documentRoot . DIRECTORY_SEPARATOR . 'large.php';
    $binaryPath = $documentRoot . DIRECTORY_SEPARATOR . 'binary.php';

    file_put_contents($firstPath, $formatted);
    file_put_contents($secondPath, $compact);
    file_put_contents($largePath, str_repeat("plain text line\n", 80000));
    file_put_contents($binaryPath, "<?php\n" . "\0" . "binary");

    $config = new ScanConfig([
        'document_root' => $documentRoot,
        'path' => $documentRoot,
        'scan_profile' => ScanConfig::SCAN_PROFILE_STANDARD,
        'profile' => ScanConfig::PROFILE_BALANCED,
        'action' => ScanConfig::ACTION_REPORT,
        'dry_run' => true,
        'max_file_size_mb' => 2,
        'enable_normalized_hash' => 'Y',
        'normalized_hash_max_file_size_mb' => 1,
    ]);
    $scanner = new Scanner();
    $first = $scanner->scanFile($firstPath, $config)->toArray();
    $second = $scanner->scanFile($secondPath, $config)->toArray();
    $large = $scanner->scanFile($largePath, $config)->toArray();
    $binary = $scanner->scanFile($binaryPath, $config)->toArray();
    $disabled = $scanner->scanFile($firstPath, new ScanConfig([
        'document_root' => $documentRoot,
        'path' => $documentRoot,
        'scan_profile' => ScanConfig::SCAN_PROFILE_STANDARD,
        'profile' => ScanConfig::PROFILE_BALANCED,
        'action' => ScanConfig::ACTION_REPORT,
        'dry_run' => true,
        'max_file_size_mb' => 2,
        'enable_normalized_hash' => 'N',
        'normalized_hash_max_file_size_mb' => 1,
    ]))->toArray();

    $expectedNormalizedHash = hash('sha256', preg_replace('/\s+/', '', $formatted));

    if (
        ($first['file_hash'] ?? '') === ($second['file_hash'] ?? '')
        || ($first['normalized_hash'] ?? null) !== $expectedNormalizedHash
        || ($second['normalized_hash'] ?? null) !== $expectedNormalizedHash
        || array_key_exists('normalized_hash', $large) === false
        || $large['normalized_hash'] !== null
        || $binary['normalized_hash'] !== null
        || $disabled['normalized_hash'] !== null
    ) {
        delement_antivirus_normalized_hash_fail('Normalized hash behavior is wrong', [
            'first' => $first,
            'second' => $second,
            'large' => $large,
            'binary' => $binary,
            'disabled' => $disabled,
            'expected_normalized_hash' => $expectedNormalizedHash,
        ]);
    }

    $_SERVER['DOCUMENT_ROOT'] = $documentRoot;
    $command = new ScanCommand($documentRoot, [
        'scan_path' => $documentRoot,
        'scan_profile' => ScanConfig::SCAN_PROFILE_STANDARD,
        'profile' => ScanConfig::PROFILE_BALANCED,
        'action' => ScanConfig::ACTION_REPORT,
        'dry_run' => 'Y',
        'quarantine_path' => $root . DIRECTORY_SEPARATOR . 'quarantine',
        'signatures_path' => '',
        'exclude_paths' => '',
        'batch_size' => '2',
        'max_file_size_mb' => '2',
        'enable_normalized_hash' => 'Y',
        'normalized_hash_max_file_size_mb' => '5',
    ], $moduleRoot);
    $cli = $command->execute([
        'scan.php',
        '--path=' . $documentRoot,
        '--json',
        '--disable-normalized-hash',
        '--normalized-hash-max-file-size-mb=1',
    ]);
    $payload = json_decode((string)$cli['stdout'], true);

    if (
        ($cli['exit_code'] ?? null) !== ScanCommand::EXIT_OK
        || !is_array($payload)
        || (($payload['enable_normalized_hash'] ?? true) !== false)
        || ((int)($payload['normalized_hash_max_file_size_bytes'] ?? 0) !== 1024 * 1024)
        || empty($payload['report_path'])
        || !is_file((string)$payload['report_path'])
    ) {
        delement_antivirus_normalized_hash_fail('CLI normalized hash flags failed', [
            'cli' => $cli,
            'payload' => $payload,
        ]);
    }

    $report = json_decode((string)file_get_contents((string)$payload['report_path']), true);
    $reportConfig = isset($report['config']) && is_array($report['config']) ? $report['config'] : [];

    if (($reportConfig['enable_normalized_hash'] ?? true) !== false) {
        delement_antivirus_normalized_hash_fail('Disabled CLI report config must contain enable_normalized_hash=false', [
            'config' => $reportConfig,
            'payload' => $payload,
        ]);
    }

    $reportResults = isset($report['results']) && is_array($report['results']) ? $report['results'] : [];

    foreach ($reportResults as $result) {
        if (is_array($result) && !array_key_exists('normalized_hash', $result)) {
            delement_antivirus_normalized_hash_fail('Report result misses normalized_hash field', [
                'result' => $result,
            ]);
        }

        if (is_array($result) && $result['normalized_hash'] !== null) {
            delement_antivirus_normalized_hash_fail('CLI --disable-normalized-hash must write null normalized_hash', [
                'result' => $result,
            ]);
        }
    }

    $cliEnabled = $command->execute([
        'scan.php',
        '--path=' . $documentRoot,
        '--json',
        '--enable-normalized-hash',
        '--normalized-hash-max-file-size-mb=1',
    ]);
    $enabledPayload = json_decode((string)$cliEnabled['stdout'], true);

    if (
        ($cliEnabled['exit_code'] ?? null) !== ScanCommand::EXIT_OK
        || !is_array($enabledPayload)
        || (($enabledPayload['enable_normalized_hash'] ?? false) !== true)
        || empty($enabledPayload['report_path'])
        || !is_file((string)$enabledPayload['report_path'])
    ) {
        delement_antivirus_normalized_hash_fail('CLI --enable-normalized-hash failed', [
            'cli' => $cliEnabled,
            'payload' => $enabledPayload,
        ]);
    }

    $enabledReport = json_decode((string)file_get_contents((string)$enabledPayload['report_path']), true);
    $enabledReportConfig = isset($enabledReport['config']) && is_array($enabledReport['config']) ? $enabledReport['config'] : [];

    if (($enabledReportConfig['enable_normalized_hash'] ?? false) !== true) {
        delement_antivirus_normalized_hash_fail('Enabled CLI report config must contain enable_normalized_hash=true', [
            'config' => $enabledReportConfig,
            'payload' => $enabledPayload,
        ]);
    }

    $enabledResults = isset($enabledReport['results']) && is_array($enabledReport['results']) ? $enabledReport['results'] : [];
    $enabledHashesByName = [];

    foreach ($enabledResults as $result) {
        if (!is_array($result)) {
            continue;
        }

        $enabledHashesByName[basename((string)($result['file_path'] ?? ''))] = $result['normalized_hash'] ?? null;
    }

    if (
        ($enabledHashesByName['formatted.php'] ?? null) !== $expectedNormalizedHash
        || ($enabledHashesByName['compact.php'] ?? null) !== $expectedNormalizedHash
        || !array_key_exists('large.php', $enabledHashesByName)
        || $enabledHashesByName['large.php'] !== null
        || !array_key_exists('binary.php', $enabledHashesByName)
        || $enabledHashesByName['binary.php'] !== null
    ) {
        delement_antivirus_normalized_hash_fail('Enabled CLI report normalized_hash values are wrong', [
            'hashes_by_name' => $enabledHashesByName,
            'expected_normalized_hash' => $expectedNormalizedHash,
        ]);
    }

    echo json_encode([
        'normalized_hash' => 'ok',
        'file_hashes_differ' => ($first['file_hash'] ?? '') !== ($second['file_hash'] ?? ''),
        'normalized_hash_value' => $expectedNormalizedHash,
        'large_is_null' => $large['normalized_hash'] === null,
        'binary_is_null' => $binary['normalized_hash'] === null,
        'cli_disable_normalized_hash' => $payload['enable_normalized_hash'],
        'cli_enable_normalized_hash' => $enabledPayload['enable_normalized_hash'],
        'cli_normalized_hash_max_file_size_bytes' => $payload['normalized_hash_max_file_size_bytes'],
        'json_report_enabled_hash' => $enabledHashesByName['formatted.php'],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
} finally {
    delement_antivirus_normalized_hash_remove_tree($root);
}
