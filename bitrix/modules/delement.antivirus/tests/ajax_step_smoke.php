<?php

use Delement\Antivirus\Admin\AjaxController;
use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\File\FileCollector;
use Delement\Antivirus\Report\ReportManager;
use Delement\Antivirus\Scanner\ScanSessionStore;

require_once __DIR__ . '/../lib/Storage/RuntimeDirectory.php';
require_once __DIR__ . '/../lib/Config/ScanConfig.php';
require_once __DIR__ . '/../lib/File/FileTypeDetector.php';
require_once __DIR__ . '/../lib/File/FileFilter.php';
require_once __DIR__ . '/../lib/File/FileCollector.php';
require_once __DIR__ . '/../lib/File/FileReader.php';
require_once __DIR__ . '/../lib/Detection/Severity.php';
require_once __DIR__ . '/../lib/Detection/Verdict.php';
require_once __DIR__ . '/../lib/Detection/Finding.php';
require_once __DIR__ . '/../lib/Detection/RuleEngine.php';
require_once __DIR__ . '/../lib/Detection/Detector.php';
require_once __DIR__ . '/../lib/Detection/SignatureLoader.php';
require_once __DIR__ . '/../lib/Scanner/ScanResult.php';
require_once __DIR__ . '/../lib/Scanner/Scanner.php';
require_once __DIR__ . '/../lib/Scanner/ScanActionApplier.php';
require_once __DIR__ . '/../lib/Scanner/ScanSessionStore.php';
require_once __DIR__ . '/../lib/Scanner/ScanRunService.php';
require_once __DIR__ . '/../lib/Report/JsonReportWriter.php';
require_once __DIR__ . '/../lib/Report/ReportManager.php';
require_once __DIR__ . '/../lib/Whitelist/WhitelistManager.php';
require_once __DIR__ . '/../lib/Quarantine/QuarantineManager.php';
require_once __DIR__ . '/../lib/Admin/AjaxController.php';

function delement_antivirus_ajax_step_remove_tree(string $path): void
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

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'delement_antivirus_ajax_step_' . getmypid();
$documentRoot = $root . DIRECTORY_SEPARATOR . 'site';
$moduleRoot = $root . DIRECTORY_SEPARATOR . 'module';

delement_antivirus_ajax_step_remove_tree($root);

try {
    if (!is_dir($documentRoot . DIRECTORY_SEPARATOR . 'upload') && !mkdir($documentRoot . DIRECTORY_SEPARATOR . 'upload', 0777, true) && !is_dir($documentRoot . DIRECTORY_SEPARATOR . 'upload')) {
        throw new RuntimeException('Cannot create fixture directory');
    }

    file_put_contents($documentRoot . DIRECTORY_SEPARATOR . 'index.php', '<?php echo "ok";');
    file_put_contents($documentRoot . DIRECTORY_SEPARATOR . 'upload' . DIRECTORY_SEPARATOR . 'probe.php', '<?php echo "probe";');

    $config = new ScanConfig([
        'document_root' => $documentRoot,
        'path' => $documentRoot,
        'scan_profile' => ScanConfig::SCAN_PROFILE_DEEP,
        'profile' => ScanConfig::PROFILE_BALANCED,
        'action' => ScanConfig::ACTION_REPORT,
        'dry_run' => true,
        'exclude_paths' => [],
        'batch_size' => 1,
        'max_file_size_mb' => 1,
    ]);
    $store = new ScanSessionStore($moduleRoot);
    $session = $store->createActive($config, 1);
    $session['status'] = 'running';
    $session['files'] = [];
    $session['discovery_state'] = (new FileCollector())->createDiscoveryState([$documentRoot]);
    $session['discovery_done'] = false;
    $session['total_files_estimated'] = 0;
    $store->saveActive($session);

    $controller = new AjaxController('delement.antivirus', $documentRoot, $store, new ReportManager($moduleRoot), $moduleRoot);
    $responses = [];

    do {
        $response = $controller->handle('scan_step', ['scan_id' => $session['scan_id']], 1);
        $responses[] = [
            'status' => $response['status'],
            'processed' => $response['processed_files'],
            'total' => $response['total_files_estimated'],
            'discovered' => $response['files_discovered'],
            'discovery_done' => $response['discovery_done'],
        ];
    } while (($response['status'] ?? '') === 'running' && count($responses) < 10);

    if (
        ($responses[0]['status'] ?? '') !== 'running'
        || ($responses[0]['total'] ?? -1) !== 0
        || ($responses[0]['discovered'] ?? 0) < 1
        || ($response['status'] ?? '') !== 'finished'
        || ($response['processed_files'] ?? 0) !== 2
        || ($response['total_files_estimated'] ?? 0) !== 2
        || count($responses) < 2
    ) {
        throw new RuntimeException('AJAX step scanning did not finish incrementally');
    }

    echo json_encode($responses, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
} catch (Throwable $exception) {
    fwrite(STDERR, $exception->getMessage() . PHP_EOL);
    exit(1);
} finally {
    delement_antivirus_ajax_step_remove_tree($root);
}
