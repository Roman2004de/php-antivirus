<?php

use Delement\Antivirus\Admin\AjaxController;
use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\Quarantine\QuarantineManager;
use Delement\Antivirus\Report\ReportManager;
use Delement\Antivirus\Scanner\ScanSessionStore;

require_once __DIR__ . '/../lib/Storage/RuntimeDirectory.php';
require_once __DIR__ . '/../lib/Config/ScanConfig.php';
require_once __DIR__ . '/../lib/File/FileTypeDetector.php';
require_once __DIR__ . '/../lib/File/FileFilter.php';
require_once __DIR__ . '/../lib/File/FileCollector.php';
require_once __DIR__ . '/../lib/File/FileReader.php';
require_once __DIR__ . '/../lib/Detection/RuleEngine.php';
require_once __DIR__ . '/../lib/Detection/Detector.php';
require_once __DIR__ . '/../lib/Detection/SignatureLoader.php';
require_once __DIR__ . '/../lib/Scanner/ScanResult.php';
require_once __DIR__ . '/../lib/Scanner/Scanner.php';
require_once __DIR__ . '/../lib/Scanner/ScanActionApplier.php';
require_once __DIR__ . '/../lib/Quarantine/QuarantineManager.php';
require_once __DIR__ . '/../lib/Report/JsonReportWriter.php';
require_once __DIR__ . '/../lib/Report/ReportManager.php';
require_once __DIR__ . '/../lib/Scanner/ScanSessionStore.php';
require_once __DIR__ . '/../lib/Whitelist/WhitelistManager.php';
require_once __DIR__ . '/../lib/Scanner/ScanRunService.php';
require_once __DIR__ . '/../lib/Admin/AjaxController.php';

function delement_antivirus_delete_smoke_remove_tree(string $path): void
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

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'delement_antivirus_delete_action_smoke_' . getmypid();
$documentRoot = $root . DIRECTORY_SEPARATOR . 'site';
$moduleRoot = $root . DIRECTORY_SEPARATOR . 'module';
$uploadPath = $documentRoot . DIRECTORY_SEPARATOR . 'upload';
$quarantinePath = $root . DIRECTORY_SEPARATOR . 'quarantine';

delement_antivirus_delete_smoke_remove_tree($root);

if (!is_dir($uploadPath) && !mkdir($uploadPath, 0777, true) && !is_dir($uploadPath)) {
    fwrite(STDERR, 'Cannot create fixture directory' . PHP_EOL);
    exit(1);
}

$deleteFile = $uploadPath . DIRECTORY_SEPARATOR . 'delete.php';
$dryRunFile = $uploadPath . DIRECTORY_SEPARATOR . 'dry-run.php';
file_put_contents($deleteFile, '<?php echo "delete";');
file_put_contents($dryRunFile, '<?php echo "dry-run";');

$controller = new AjaxController(
    'delement.antivirus',
    $documentRoot,
    new ScanSessionStore($moduleRoot),
    new ReportManager($moduleRoot),
    $moduleRoot
);
$method = new ReflectionMethod($controller, 'applyConfiguredAction');
$method->setAccessible(true);

$baseResult = [
    'file_path' => $deleteFile,
    'file_hash' => hash_file('sha256', $deleteFile),
    'status' => 'malicious',
    'score' => 8,
    'severity' => 'high',
    'findings' => [
        [
            'signature_id' => 'smoke_delete_signature',
            'category' => 'smoke',
            'severity' => 'high',
            'score' => 8,
        ],
    ],
    'action' => 'report',
    'planned_action' => 'report',
    'error' => '',
];

$deleteConfig = new ScanConfig([
    'document_root' => $documentRoot,
    'path' => $documentRoot,
    'profile' => ScanConfig::PROFILE_BALANCED,
    'action' => ScanConfig::ACTION_DELETE,
    'dry_run' => false,
    'quarantine_path' => $quarantinePath,
    'exclude_paths' => [],
    'max_file_size_mb' => 1,
]);

$deleteResult = $method->invoke($controller, $baseResult, $deleteConfig, 'scan_delete_smoke');
$quarantineItems = (new QuarantineManager($quarantinePath, $documentRoot))->listItems();
$deleteItem = $quarantineItems[0] ?? [];

if (
    is_file($deleteFile)
    || ($deleteResult['action'] ?? '') !== ScanConfig::ACTION_DELETE
    || ($deleteResult['action_status'] ?? '') !== 'done'
    || ($deleteResult['delete_id'] ?? '') === ''
    || ($deleteItem['status'] ?? '') !== QuarantineManager::STATUS_DELETED
    || ($deleteItem['action'] ?? '') !== ScanConfig::ACTION_DELETE
    || ($deleteItem['action_status'] ?? '') !== 'done'
    || !empty($deleteItem['payload_exists'])
) {
    fwrite(STDERR, json_encode(['result' => $deleteResult, 'items' => $quarantineItems], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    delement_antivirus_delete_smoke_remove_tree($root);
    exit(1);
}

$dryRunResultInput = $baseResult;
$dryRunResultInput['file_path'] = $dryRunFile;
$dryRunResultInput['file_hash'] = hash_file('sha256', $dryRunFile);
$dryRunConfig = new ScanConfig([
    'document_root' => $documentRoot,
    'path' => $documentRoot,
    'profile' => ScanConfig::PROFILE_BALANCED,
    'action' => ScanConfig::ACTION_DELETE,
    'dry_run' => true,
    'quarantine_path' => $quarantinePath,
    'exclude_paths' => [],
    'max_file_size_mb' => 1,
]);

$dryRunResult = $method->invoke($controller, $dryRunResultInput, $dryRunConfig, 'scan_delete_dry_run_smoke');

if (
    !is_file($dryRunFile)
    || ($dryRunResult['planned_action'] ?? '') !== ScanConfig::ACTION_DELETE
    || ($dryRunResult['action'] ?? '') !== ScanConfig::ACTION_REPORT
    || ($dryRunResult['action_status'] ?? '') !== 'dry_run'
) {
    fwrite(STDERR, json_encode(['dry_run_result' => $dryRunResult], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    delement_antivirus_delete_smoke_remove_tree($root);
    exit(1);
}

echo json_encode(
    [
        'delete_action' => $deleteResult['action'],
        'delete_status' => $deleteResult['action_status'],
        'metadata_status' => $deleteItem['status'],
        'dry_run_action' => $dryRunResult['action'],
        'dry_run_status' => $dryRunResult['action_status'],
    ],
    JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
) . PHP_EOL;

delement_antivirus_delete_smoke_remove_tree($root);
