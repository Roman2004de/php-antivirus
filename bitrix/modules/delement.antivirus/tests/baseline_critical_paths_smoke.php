<?php

use Delement\Antivirus\Baseline\BaselineManager;
use Delement\Antivirus\Baseline\BaselineStorage;
use Delement\Antivirus\Config\ScanConfig;

require_once __DIR__ . '/../lib/Storage/RuntimeDirectory.php';
require_once __DIR__ . '/../lib/Config/ScanConfig.php';
require_once __DIR__ . '/../lib/File/FileTypeDetector.php';
require_once __DIR__ . '/../lib/File/FileFilter.php';
require_once __DIR__ . '/../lib/Detection/Severity.php';
require_once __DIR__ . '/../lib/Detection/Verdict.php';
require_once __DIR__ . '/../lib/Detection/Finding.php';
require_once __DIR__ . '/../lib/Scanner/ScanResult.php';
require_once __DIR__ . '/../lib/Baseline/BaselineRecord.php';
require_once __DIR__ . '/../lib/Baseline/BaselineStorage.php';
require_once __DIR__ . '/../lib/Detection/Baseline/BaselineFindingFactory.php';
require_once __DIR__ . '/../lib/Detection/Baseline/BaselineAnalyzer.php';
require_once __DIR__ . '/../lib/Baseline/BaselineManager.php';

function delement_antivirus_baseline_critical_remove_tree(string $path): void
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

function delement_antivirus_baseline_critical_fail(string $message, array $context = []): void
{
    fwrite(STDERR, $message . PHP_EOL);

    if (!empty($context)) {
        fwrite(STDERR, json_encode($context, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL);
    }

    exit(1);
}

function delement_antivirus_baseline_critical_findings(array $report, string $signatureId): array
{
    $matches = [];

    foreach ((array)($report['results'] ?? []) as $result) {
        foreach ((array)($result['findings'] ?? []) as $finding) {
            if (is_array($finding) && (string)($finding['signature_id'] ?? '') === $signatureId) {
                $matches[] = [
                    'result' => $result,
                    'finding' => $finding,
                ];
            }
        }
    }

    return $matches;
}

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'delement_antivirus_baseline_critical_' . getmypid();
$documentRoot = $root . DIRECTORY_SEPARATOR . 'site';
$moduleRoot = $root . DIRECTORY_SEPARATOR . 'module';

delement_antivirus_baseline_critical_remove_tree($root);

try {
    foreach ([
        $documentRoot . DIRECTORY_SEPARATOR . 'local' . DIRECTORY_SEPARATOR . 'php_interface',
        $documentRoot . DIRECTORY_SEPARATOR . 'upload',
        $documentRoot . DIRECTORY_SEPARATOR . 'bitrix' . DIRECTORY_SEPARATOR . 'tools',
        $documentRoot . DIRECTORY_SEPARATOR . 'bitrix' . DIRECTORY_SEPARATOR . 'admin',
        $moduleRoot,
    ] as $directory) {
        if (!mkdir($directory, 0777, true) && !is_dir($directory)) {
            delement_antivirus_baseline_critical_fail('Cannot create fixture directory', ['directory' => $directory]);
        }
    }

    $_SERVER['DOCUMENT_ROOT'] = $documentRoot;
    $initPath = $documentRoot . DIRECTORY_SEPARATOR . 'local' . DIRECTORY_SEPARATOR . 'php_interface' . DIRECTORY_SEPARATOR . 'init.php';
    $htaccessPath = $documentRoot . DIRECTORY_SEPARATOR . '.htaccess';
    file_put_contents($initPath, "<?php\n// baseline\n");
    file_put_contents($htaccessPath, "Options -Indexes\n");
    file_put_contents($documentRoot . DIRECTORY_SEPARATOR . 'index.php', "<?php\necho 'ok';\n");

    $config = new ScanConfig([
        'document_root' => $documentRoot,
        'path' => $documentRoot,
        'scan_profile' => ScanConfig::SCAN_PROFILE_DEEP,
        'profile' => ScanConfig::PROFILE_STRICT,
        'action' => ScanConfig::ACTION_REPORT,
        'dry_run' => true,
        'enable_normalized_hash' => 'Y',
        'exclude_paths' => '',
        'max_file_size_mb' => 10,
    ]);
    $manager = new BaselineManager(new BaselineStorage($moduleRoot));
    $manager->createBaseline($config);

    file_put_contents($initPath, "<?php\n// changed\n");
    file_put_contents($htaccessPath, "AddHandler application/x-httpd-php .jpg\n");
    file_put_contents($documentRoot . DIRECTORY_SEPARATOR . 'upload' . DIRECTORY_SEPARATOR . 'shell.php', "<?php\necho 'upload php';\n");
    file_put_contents($documentRoot . DIRECTORY_SEPARATOR . 'bitrix' . DIRECTORY_SEPARATOR . 'tools' . DIRECTORY_SEPARATOR . 'loader.php', "<?php\necho 'loader';\n");
    file_put_contents($documentRoot . DIRECTORY_SEPARATOR . 'bitrix' . DIRECTORY_SEPARATOR . 'admin' . DIRECTORY_SEPARATOR . 'extra.php', "<?php\necho 'admin';\n");

    $report = $manager->checkBaseline($config);
    $phpUpload = delement_antivirus_baseline_critical_findings($report, 'baseline_php_in_upload');
    $unknownTools = delement_antivirus_baseline_critical_findings($report, 'baseline_unknown_file_in_tools');
    $criticalPath = delement_antivirus_baseline_critical_findings($report, 'baseline_critical_path_modified');

    if (
        empty($phpUpload)
        || empty($unknownTools)
        || count($criticalPath) < 4
        || (int)($report['summary']['critical_changes'] ?? 0) < 4
        || !in_array('engine:baseline', (array)($phpUpload[0]['finding']['tags'] ?? []), true)
        || !in_array('risk:baseline_change', (array)($phpUpload[0]['finding']['tags'] ?? []), true)
        || !in_array('path:upload', (array)($phpUpload[0]['finding']['tags'] ?? []), true)
        || !in_array('risk:executable_upload', (array)($phpUpload[0]['finding']['tags'] ?? []), true)
        || (string)($phpUpload[0]['finding']['severity'] ?? '') !== 'critical'
    ) {
        delement_antivirus_baseline_critical_fail('Critical baseline findings are wrong', [
            'summary' => $report['summary'] ?? [],
            'php_upload' => $phpUpload,
            'unknown_tools' => $unknownTools,
            'critical_path_count' => count($criticalPath),
        ]);
    }

    echo json_encode([
        'baseline_critical_paths' => 'ok',
        'critical_changes' => $report['summary']['critical_changes'],
        'php_upload_findings' => count($phpUpload),
        'unknown_tools_findings' => count($unknownTools),
        'critical_path_findings' => count($criticalPath),
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL;
} finally {
    delement_antivirus_baseline_critical_remove_tree($root);
}
