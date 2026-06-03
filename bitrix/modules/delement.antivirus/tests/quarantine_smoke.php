<?php

use Delement\Antivirus\Quarantine\QuarantineManager;

require_once __DIR__ . '/../lib/Quarantine/QuarantineManager.php';

function delement_antivirus_remove_tree(string $path): void
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

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'delement_antivirus_quarantine_smoke_' . getmypid();
$documentRoot = $root . DIRECTORY_SEPARATOR . 'site';
$uploadPath = $documentRoot . DIRECTORY_SEPARATOR . 'upload';
$bitrixPath = $documentRoot . DIRECTORY_SEPARATOR . 'bitrix';
$quarantinePath = $root . DIRECTORY_SEPARATOR . 'quarantine';

delement_antivirus_remove_tree($root);

if (!is_dir($uploadPath) && !mkdir($uploadPath, 0777, true) && !is_dir($uploadPath)) {
    fwrite(STDERR, 'Cannot create upload directory' . PHP_EOL);
    exit(1);
}

if (!is_dir($bitrixPath) && !mkdir($bitrixPath, 0777, true) && !is_dir($bitrixPath)) {
    fwrite(STDERR, 'Cannot create bitrix directory' . PHP_EOL);
    exit(1);
}

$restoreFile = $uploadPath . DIRECTORY_SEPARATOR . 'restore.php';
$deleteFile = $uploadPath . DIRECTORY_SEPARATOR . 'delete.php';
$criticalFile = $bitrixPath . DIRECTORY_SEPARATOR . '.settings.php';
file_put_contents($restoreFile, '<?php echo "restore";');
file_put_contents($deleteFile, '<?php echo "delete";');
file_put_contents($criticalFile, '<?php return ["critical" => true];');

$manager = new QuarantineManager($quarantinePath, $documentRoot);
$scanResult = [
    'file_path' => $restoreFile,
    'file_hash' => hash_file('sha256', $restoreFile),
    'status' => 'malicious',
    'score' => 8,
    'severity' => 'high',
    'findings' => [
        [
            'signature_id' => 'smoke_signature',
            'category' => 'smoke',
            'severity' => 'high',
            'score' => 8,
        ],
    ],
];

$restoredItem = $manager->quarantine($restoreFile, $scanResult, 'scan_smoke_restore');

if (
    is_file($restoreFile)
    || empty($restoredItem['id'])
    || !is_file((string)$restoredItem['quarantine_path'])
    || empty($restoredItem['source_hash_before'])
    || ($restoredItem['source_hash_before'] ?? '') !== ($restoredItem['payload_hash_after'] ?? '')
    || empty($restoredItem['checksum_verified'])
) {
    fwrite(STDERR, 'Quarantine move failed' . PHP_EOL);
    delement_antivirus_remove_tree($root);
    exit(1);
}

$manager->restore((string)$restoredItem['id'], false, ['user_id' => 7, 'source' => 'smoke']);
$loadedRestored = $manager->load((string)$restoredItem['id']);

if (
    !is_file($restoreFile)
    || ($loadedRestored['status'] ?? '') !== QuarantineManager::STATUS_RESTORED
    || empty($loadedRestored['restore_checksum_verified'])
    || (($loadedRestored['events'][0]['event'] ?? '') !== 'restore')
    || (($loadedRestored['events'][0]['user_id'] ?? 0) !== 7)
) {
    fwrite(STDERR, 'Quarantine restore failed' . PHP_EOL);
    delement_antivirus_remove_tree($root);
    exit(1);
}

$scanResult['file_path'] = $deleteFile;
$scanResult['file_hash'] = hash_file('sha256', $deleteFile);
$deletedItem = $manager->quarantine($deleteFile, $scanResult, 'scan_smoke_delete');
$manager->deletePayload((string)$deletedItem['id'], ['user_id' => 8, 'source' => 'smoke']);
$loadedDeleted = $manager->load((string)$deletedItem['id']);

if (
    is_file($deleteFile)
    || is_file((string)$deletedItem['quarantine_path'])
    || ($loadedDeleted['status'] ?? '') !== QuarantineManager::STATUS_DELETED
    || empty($loadedDeleted['payload_hash_before_delete'])
    || (($loadedDeleted['events'][0]['event'] ?? '') !== 'delete_payload')
    || (($loadedDeleted['events'][0]['user_id'] ?? 0) !== 8)
) {
    fwrite(STDERR, 'Quarantine delete failed' . PHP_EOL);
    delement_antivirus_remove_tree($root);
    exit(1);
}

$scanResult['file_path'] = $criticalFile;
$scanResult['file_hash'] = hash_file('sha256', $criticalFile);
$criticalItem = $manager->quarantine($criticalFile, $scanResult, 'scan_smoke_critical_restore');
$criticalRestoreBlocked = false;

try {
    $manager->restore((string)$criticalItem['id']);
} catch (RuntimeException $exception) {
    $criticalRestoreBlocked = $exception->getMessage() === 'quarantine_restore_critical_confirmation_required';
}

if (!$criticalRestoreBlocked || is_file($criticalFile) || empty($manager->load((string)$criticalItem['id'])['critical_restore'])) {
    fwrite(STDERR, 'Critical restore was not blocked' . PHP_EOL);
    delement_antivirus_remove_tree($root);
    exit(1);
}

$manager->restore((string)$criticalItem['id'], true, ['user_id' => 9, 'source' => 'smoke']);
$loadedCritical = $manager->load((string)$criticalItem['id']);
$items = $manager->listItems();

if (
    !is_file($criticalFile)
    || ($loadedCritical['status'] ?? '') !== QuarantineManager::STATUS_RESTORED
    || empty($loadedCritical['critical_restore_confirmed'])
    || (($loadedCritical['events'][0]['event'] ?? '') !== 'restore')
    || count($items) !== 3
) {
    fwrite(STDERR, 'Critical restore confirmation failed' . PHP_EOL);
    delement_antivirus_remove_tree($root);
    exit(1);
}

if (DIRECTORY_SEPARATOR !== '\\') {
    $itemDirectoryMode = fileperms(dirname((string)$criticalItem['quarantine_path'])) & 0777;
    $metaMode = fileperms(dirname((string)$criticalItem['quarantine_path']) . DIRECTORY_SEPARATOR . 'meta.json') & 0777;

    if ($itemDirectoryMode !== 0700 || $metaMode !== 0600) {
        fwrite(STDERR, 'Quarantine permissions are not strict enough' . PHP_EOL);
        delement_antivirus_remove_tree($root);
        exit(1);
    }
}

echo json_encode(
    [
        'restored_status' => $loadedRestored['status'],
        'deleted_status' => $loadedDeleted['status'],
        'critical_status' => $loadedCritical['status'],
        'critical_blocked_without_confirmation' => $criticalRestoreBlocked,
        'items' => count($items),
    ],
    JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
) . PHP_EOL;

delement_antivirus_remove_tree($root);
