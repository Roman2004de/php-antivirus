<?php

use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\Scanner\ScanSessionStore;

require_once __DIR__ . '/../lib/Storage/RuntimeDirectory.php';
require_once __DIR__ . '/../lib/Config/ScanConfig.php';
require_once __DIR__ . '/../lib/Scanner/ScanSessionStore.php';

function delement_antivirus_parallel_lock_remove_tree(string $path): void
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

$moduleRoot = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'delement_antivirus_parallel_lock_smoke_' . getmypid();

delement_antivirus_parallel_lock_remove_tree($moduleRoot);

$config = new ScanConfig([
    'path' => $moduleRoot,
    'profile' => ScanConfig::PROFILE_BALANCED,
    'action' => ScanConfig::ACTION_REPORT,
    'dry_run' => true,
    'exclude_paths' => [],
]);

$store = new ScanSessionStore($moduleRoot);
$first = $store->createActive($config, 1);
$conflict = $store->createActive($config, 2);

if (
    empty($first['scan_id'])
    || empty($conflict['active_conflict'])
    || (string)($conflict['active_session']['scan_id'] ?? '') !== (string)$first['scan_id']
) {
    fwrite(STDERR, json_encode(['first' => $first, 'conflict' => $conflict], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    delement_antivirus_parallel_lock_remove_tree($moduleRoot);
    exit(1);
}

$first['status'] = 'running';
$first['processed_files'] = 3;
$first['total_files_estimated'] = 10;
$first['current_file'] = $moduleRoot . DIRECTORY_SEPARATOR . 'file.php';
$store->saveActive($first);
$active = $store->getActiveSession();

if (($active['processed_files'] ?? 0) !== 3 || ($active['total_files_estimated'] ?? 0) !== 10) {
    fwrite(STDERR, json_encode(['active' => $active], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    delement_antivirus_parallel_lock_remove_tree($moduleRoot);
    exit(1);
}

$first['status'] = 'finished';
$first['finished_at'] = date('c');
$first['current_file'] = '';
$store->saveActive($first);

if ($store->getActiveSession() !== null) {
    fwrite(STDERR, 'Active marker was not released after finish' . PHP_EOL);
    delement_antivirus_parallel_lock_remove_tree($moduleRoot);
    exit(1);
}

$second = $store->createActive($config, 2);

if (!empty($second['active_conflict']) || empty($second['scan_id']) || (string)$second['scan_id'] === (string)$first['scan_id']) {
    fwrite(STDERR, json_encode(['second' => $second], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    delement_antivirus_parallel_lock_remove_tree($moduleRoot);
    exit(1);
}

$second['status'] = 'cancelled';
$second['finished_at'] = date('c');
$store->saveActive($second);

if ($store->getActiveSession() !== null) {
    fwrite(STDERR, 'Active marker was not released after cancel' . PHP_EOL);
    delement_antivirus_parallel_lock_remove_tree($moduleRoot);
    exit(1);
}

echo json_encode(
    [
        'first_scan_id' => $first['scan_id'],
        'conflict_error' => 'scan_already_running',
        'second_scan_id' => $second['scan_id'],
        'active_after_finish' => null,
        'active_after_cancel' => null,
    ],
    JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
) . PHP_EOL;

delement_antivirus_parallel_lock_remove_tree($moduleRoot);
