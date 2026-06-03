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
$quarantinePath = $root . DIRECTORY_SEPARATOR . 'quarantine';

delement_antivirus_remove_tree($root);

if (!is_dir($uploadPath) && !mkdir($uploadPath, 0777, true) && !is_dir($uploadPath)) {
    fwrite(STDERR, 'Cannot create upload directory' . PHP_EOL);
    exit(1);
}

$restoreFile = $uploadPath . DIRECTORY_SEPARATOR . 'restore.php';
$deleteFile = $uploadPath . DIRECTORY_SEPARATOR . 'delete.php';
file_put_contents($restoreFile, '<?php echo "restore";');
file_put_contents($deleteFile, '<?php echo "delete";');

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

if (is_file($restoreFile) || empty($restoredItem['id']) || !is_file((string)$restoredItem['quarantine_path'])) {
    fwrite(STDERR, 'Quarantine move failed' . PHP_EOL);
    delement_antivirus_remove_tree($root);
    exit(1);
}

$manager->restore((string)$restoredItem['id']);
$loadedRestored = $manager->load((string)$restoredItem['id']);

if (!is_file($restoreFile) || ($loadedRestored['status'] ?? '') !== QuarantineManager::STATUS_RESTORED) {
    fwrite(STDERR, 'Quarantine restore failed' . PHP_EOL);
    delement_antivirus_remove_tree($root);
    exit(1);
}

$scanResult['file_path'] = $deleteFile;
$scanResult['file_hash'] = hash_file('sha256', $deleteFile);
$deletedItem = $manager->quarantine($deleteFile, $scanResult, 'scan_smoke_delete');
$manager->deletePayload((string)$deletedItem['id']);
$loadedDeleted = $manager->load((string)$deletedItem['id']);
$items = $manager->listItems();

if (is_file($deleteFile) || is_file((string)$deletedItem['quarantine_path']) || ($loadedDeleted['status'] ?? '') !== QuarantineManager::STATUS_DELETED || count($items) !== 2) {
    fwrite(STDERR, 'Quarantine delete failed' . PHP_EOL);
    delement_antivirus_remove_tree($root);
    exit(1);
}

echo json_encode(
    [
        'restored_status' => $loadedRestored['status'],
        'deleted_status' => $loadedDeleted['status'],
        'items' => count($items),
    ],
    JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
) . PHP_EOL;

delement_antivirus_remove_tree($root);
