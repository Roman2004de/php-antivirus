<?php

use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\Scanner\ScanSessionStore;

require_once __DIR__ . '/../lib/Storage/RuntimeDirectory.php';
require_once __DIR__ . '/../lib/Config/ScanConfig.php';
require_once __DIR__ . '/../lib/Scanner/ScanSessionStore.php';

$moduleRoot = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'delement_antivirus_session_smoke_' . getmypid();
$sessionsPath = $moduleRoot . DIRECTORY_SEPARATOR . 'var' . DIRECTORY_SEPARATOR . 'sessions';

if (!is_dir($sessionsPath) && !mkdir($sessionsPath, 0777, true) && !is_dir($sessionsPath)) {
    fwrite(STDERR, 'Cannot create session directory' . PHP_EOL);
    exit(1);
}

$config = new ScanConfig([
    'path' => $moduleRoot,
    'profile' => ScanConfig::PROFILE_BALANCED,
    'action' => ScanConfig::ACTION_REPORT,
    'dry_run' => true,
    'exclude_paths' => [],
]);

$store = new ScanSessionStore($moduleRoot);
$session = $store->create($config, [$moduleRoot . DIRECTORY_SEPARATOR . 'index.php'], 1);
$loaded = $store->load($session['scan_id']);

$sessionFile = $sessionsPath . DIRECTORY_SEPARATOR . $session['scan_id'] . '.json';

@unlink($sessionFile);
@unlink($sessionsPath . DIRECTORY_SEPARATOR . '.htaccess');
@unlink($sessionsPath . DIRECTORY_SEPARATOR . 'index.php');
@rmdir($sessionsPath);
@unlink(dirname($sessionsPath) . DIRECTORY_SEPARATOR . '.htaccess');
@unlink(dirname($sessionsPath) . DIRECTORY_SEPARATOR . 'index.php');
@rmdir(dirname($sessionsPath));
@rmdir($moduleRoot);

if (($loaded['scan_id'] ?? '') !== $session['scan_id'] || ($loaded['total_files_estimated'] ?? 0) !== 1) {
    fwrite(STDERR, json_encode(['created' => $session, 'loaded' => $loaded], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    exit(1);
}

echo json_encode([
    'scan_id' => $loaded['scan_id'],
    'status' => $loaded['status'],
    'total_files_estimated' => $loaded['total_files_estimated'],
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
