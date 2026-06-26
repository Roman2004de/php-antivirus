<?php

use Delement\Antivirus\Cli\ScanCommand;
use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\Scanner\ScanSessionStore;

require_once __DIR__ . '/../lib/Storage/RuntimeDirectory.php';
require_once __DIR__ . '/../lib/Support/ModuleVersion.php';
require_once __DIR__ . '/../lib/Cli/ArgvParser.php';
require_once __DIR__ . '/../lib/Cli/ScanCommand.php';
require_once __DIR__ . '/../lib/Config/ScanConfig.php';
require_once __DIR__ . '/../lib/File/FileTypeDetector.php';
require_once __DIR__ . '/../lib/File/FileFilter.php';
require_once __DIR__ . '/../lib/File/FileCollector.php';
require_once __DIR__ . '/../lib/File/FileReader.php';
require_once __DIR__ . '/../lib/Detection/Severity.php';
require_once __DIR__ . '/../lib/Detection/Verdict.php';
require_once __DIR__ . '/../lib/Detection/Finding.php';
require_once __DIR__ . '/../lib/Detection/Tags/TagCatalog.php';
require_once __DIR__ . '/../lib/Detection/Tags/PathTagger.php';
require_once __DIR__ . '/../lib/Detection/Tags/FindingTagger.php';
require_once __DIR__ . '/../lib/Detection/Tags/ResultTagger.php';
require_once __DIR__ . '/../lib/Detection/RuleEngine.php';
require_once __DIR__ . '/../lib/Detection/Detector.php';
require_once __DIR__ . '/../lib/Detection/SignatureLoader.php';
require_once __DIR__ . '/../lib/Scanner/ScanResult.php';
require_once __DIR__ . '/../lib/Scanner/Scanner.php';
require_once __DIR__ . '/../lib/Scanner/ScanActionApplier.php';
require_once __DIR__ . '/../lib/Scanner/ScanSessionStore.php';
require_once __DIR__ . '/../lib/Scanner/ScanRunService.php';
require_once __DIR__ . '/../lib/Quarantine/QuarantineManager.php';
require_once __DIR__ . '/../lib/Report/JsonReportWriter.php';
require_once __DIR__ . '/../lib/Report/ReportManager.php';
require_once __DIR__ . '/../lib/Whitelist/WhitelistManager.php';

function delement_antivirus_cli_smoke_remove_tree(string $path): void
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

function delement_antivirus_cli_smoke_fail(string $message, array $context = []): void
{
    fwrite(STDERR, $message . PHP_EOL);

    if (!empty($context)) {
        fwrite(STDERR, json_encode($context, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    }

    exit(1);
}

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'delement_antivirus_cli_smoke_' . getmypid();
$documentRoot = $root . DIRECTORY_SEPARATOR . 'site';
$moduleRoot = $root . DIRECTORY_SEPARATOR . 'module';
$uploadPath = $documentRoot . DIRECTORY_SEPARATOR . 'upload';
$quarantinePath = $root . DIRECTORY_SEPARATOR . 'quarantine';
$exportReportPath = $root . DIRECTORY_SEPARATOR . 'exports' . DIRECTORY_SEPARATOR . 'report.json';

delement_antivirus_cli_smoke_remove_tree($root);

try {
    if (!mkdir($uploadPath, 0777, true) && !is_dir($uploadPath)) {
        delement_antivirus_cli_smoke_fail('Cannot create upload fixture directory');
    }

    if (!mkdir($moduleRoot, 0777, true) && !is_dir($moduleRoot)) {
        delement_antivirus_cli_smoke_fail('Cannot create module fixture directory');
    }

    if (!mkdir($moduleRoot . DIRECTORY_SEPARATOR . 'install', 0777, true) && !is_dir($moduleRoot . DIRECTORY_SEPARATOR . 'install')) {
        delement_antivirus_cli_smoke_fail('Cannot create module install fixture directory');
    }

    file_put_contents($moduleRoot . DIRECTORY_SEPARATOR . 'install' . DIRECTORY_SEPARATOR . 'version.php', "<?php\n\$arModuleVersion = ['VERSION' => '0.0.4', 'VERSION_DATE' => '2026-06-19 00:00:00'];\n");
    file_put_contents($uploadPath . DIRECTORY_SEPARATOR . 'shell.php', '<?php echo "shell";');
    file_put_contents($documentRoot . DIRECTORY_SEPARATOR . 'index.php', '<?php echo "ok";');
    $_SERVER['DOCUMENT_ROOT'] = $documentRoot;

    $moduleOptions = [
        'scan_path' => $documentRoot,
        'scan_profile' => ScanConfig::SCAN_PROFILE_STANDARD,
        'profile' => ScanConfig::PROFILE_BALANCED,
        'action' => ScanConfig::ACTION_REPORT,
        'dry_run' => 'Y',
        'quarantine_path' => $quarantinePath,
        'signatures_path' => '',
        'exclude_paths' => '',
        'batch_size' => '1',
        'max_file_size_mb' => '1',
    ];
    $command = new ScanCommand($documentRoot, $moduleOptions, $moduleRoot);

    $help = $command->execute(['scan.php', '--help']);

    if (
        ($help['exit_code'] ?? null) !== ScanCommand::EXIT_OK
        || strpos((string)$help['stdout'], '--path=PATH') === false
        || strpos((string)$help['stdout'], '--report=PATH') === false
    ) {
        delement_antivirus_cli_smoke_fail('CLI help failed', ['help' => $help]);
    }

    $version = $command->execute(['scan.php', '--version']);

    if (($version['exit_code'] ?? null) !== ScanCommand::EXIT_OK || trim((string)$version['stdout']) !== '0.0.4') {
        delement_antivirus_cli_smoke_fail('CLI version failed', ['version' => $version]);
    }

    $scan = $command->execute([
        'scan.php',
        '--path=' . $documentRoot,
        '--scan-profile=deep',
        '--profile=strict',
        '--action=report',
        '--dry-run',
        '--json',
        '--report=' . $exportReportPath,
        '--disable-prefilter',
        '--batch-size=1',
    ]);
    $scanPayload = json_decode((string)$scan['stdout'], true);

    if (
        ($scan['exit_code'] ?? null) !== ScanCommand::EXIT_FINDINGS
        || !is_array($scanPayload)
        || empty($scanPayload['success'])
        || ($scanPayload['status'] ?? '') !== 'finished'
        || ($scanPayload['found_total'] ?? 0) < 1
        || (($scanPayload['report_path'] ?? '') !== $exportReportPath)
        || !is_file($exportReportPath)
        || empty($scanPayload['runtime_report_path'])
        || !is_file((string)$scanPayload['runtime_report_path'])
        || !in_array('path:upload', (array)($scanPayload['tags'] ?? []), true)
        || (($scanPayload['enable_common_strings_prefilter'] ?? true) !== false)
    ) {
        delement_antivirus_cli_smoke_fail('CLI JSON scan failed', [
            'result' => $scan,
            'payload' => $scanPayload,
        ]);
    }

    $unsafeDelete = $command->execute([
        'scan.php',
        '--path=' . $documentRoot,
        '--action=delete',
        '--no-dry-run',
        '--json',
    ]);
    $unsafeDeletePayload = json_decode((string)$unsafeDelete['stdout'], true);

    if (
        ($unsafeDelete['exit_code'] ?? null) !== ScanCommand::EXIT_USAGE
        || (($unsafeDeletePayload['error'] ?? '') !== 'cli_force_required_for_destructive_action')
    ) {
        delement_antivirus_cli_smoke_fail('CLI destructive action guard failed', [
            'result' => $unsafeDelete,
            'payload' => $unsafeDeletePayload,
        ]);
    }

    $config = new ScanConfig([
        'document_root' => $documentRoot,
        'path' => $documentRoot,
        'profile' => ScanConfig::PROFILE_BALANCED,
        'action' => ScanConfig::ACTION_REPORT,
        'dry_run' => true,
        'exclude_paths' => [],
    ]);
    $store = new ScanSessionStore($moduleRoot);
    $active = $store->createActive($config, 0);
    $conflict = $command->execute([
        'scan.php',
        '--path=' . $documentRoot,
        '--json',
    ]);
    $conflictPayload = json_decode((string)$conflict['stdout'], true);

    $active['status'] = 'cancelled';
    $active['finished_at'] = date('c');
    $store->saveActive($active);

    if (
        ($conflict['exit_code'] ?? null) !== ScanCommand::EXIT_SCAN_CONFLICT
        || (($conflictPayload['error'] ?? '') !== 'scan_already_running')
    ) {
        delement_antivirus_cli_smoke_fail('CLI parallel scan guard failed', [
            'result' => $conflict,
            'payload' => $conflictPayload,
        ]);
    }

    echo json_encode([
        'help' => 'ok',
        'version' => trim((string)$version['stdout']),
        'scan_exit_code' => $scan['exit_code'],
        'found_total' => $scanPayload['found_total'],
        'report_path' => $scanPayload['report_path'],
        'tags' => $scanPayload['tags'],
        'enable_common_strings_prefilter' => $scanPayload['enable_common_strings_prefilter'],
        'force_guard' => $unsafeDeletePayload['error'],
        'conflict_guard' => $conflictPayload['error'],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
} finally {
    delement_antivirus_cli_smoke_remove_tree($root);
}
