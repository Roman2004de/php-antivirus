<?php

use Delement\Antivirus\Whitelist\WhitelistManager;

require_once __DIR__ . '/../lib/Storage/RuntimeDirectory.php';
require_once __DIR__ . '/../lib/Detection/Severity.php';
require_once __DIR__ . '/../lib/Detection/Verdict.php';
require_once __DIR__ . '/../lib/Whitelist/WhitelistManager.php';

function delement_antivirus_whitelist_remove_tree(string $path): void
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

$moduleRoot = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'delement_antivirus_whitelist_smoke_' . getmypid();
delement_antivirus_whitelist_remove_tree($moduleRoot);

$filePath = $moduleRoot . DIRECTORY_SEPARATOR . 'site' . DIRECTORY_SEPARATOR . 'upload' . DIRECTORY_SEPARATOR . 'shell.php';
$fileHash = hash('sha256', 'fixture');
$thresholds = ['suspicious' => 4, 'malicious' => 8];
$result = [
    'file_path' => $filePath,
    'file_hash' => $fileHash,
    'status' => 'malicious',
    'score' => 10,
    'severity' => 'high',
    'findings' => [
        [
            'signature_id' => 'signature_one',
            'category' => 'smoke',
            'severity' => 'high',
            'score' => 8,
            'excerpt' => '',
        ],
        [
            'signature_id' => 'signature_two',
            'category' => 'smoke',
            'severity' => 'low',
            'score' => 2,
            'excerpt' => '',
        ],
    ],
];

$manager = new WhitelistManager($moduleRoot);
$fileSignatureRule = $manager->addRule(WhitelistManager::TYPE_FILE_SIGNATURE, [
    'path' => $filePath,
    'hash' => $fileHash,
    'signature_id' => 'signature_one',
]);

$filtered = $manager->filterResult($result, $thresholds);

if (($filtered['status'] ?? '') !== 'low_risk' || ($filtered['score'] ?? 0) !== 2 || count($filtered['findings'] ?? []) !== 1 || ($filtered['whitelisted_total'] ?? 0) !== 1) {
    fwrite(STDERR, json_encode($filtered, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    delement_antivirus_whitelist_remove_tree($moduleRoot);
    exit(1);
}

$regexRule = $manager->addRule(WhitelistManager::TYPE_PATH_REGEX, [
    'pattern' => '#/upload/.*\.php$#',
]);

$fullyFiltered = $manager->filterResult($result, $thresholds);

if (($fullyFiltered['status'] ?? '') !== 'clean' || ($fullyFiltered['score'] ?? 1) !== 0 || count($fullyFiltered['findings'] ?? []) !== 0 || ($fullyFiltered['whitelisted_total'] ?? 0) !== 2) {
    fwrite(STDERR, json_encode($fullyFiltered, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    delement_antivirus_whitelist_remove_tree($moduleRoot);
    exit(1);
}

try {
    $manager->addRule(WhitelistManager::TYPE_PATH_REGEX, [
        'pattern' => '#unterminated',
    ]);
    fwrite(STDERR, 'Invalid regex was accepted' . PHP_EOL);
    delement_antivirus_whitelist_remove_tree($moduleRoot);
    exit(1);
} catch (RuntimeException $exception) {
    // Expected.
}

$manager->deactivateRule((string)$regexRule['id']);
$afterDeactivate = $manager->filterResult($result, $thresholds);

if (($afterDeactivate['status'] ?? '') !== 'low_risk' || count($afterDeactivate['findings'] ?? []) !== 1) {
    fwrite(STDERR, json_encode($afterDeactivate, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    delement_antivirus_whitelist_remove_tree($moduleRoot);
    exit(1);
}

$manager->activateRule((string)$regexRule['id']);
$afterActivate = $manager->filterResult($result, $thresholds);

if (($afterActivate['status'] ?? '') !== 'clean' || count($afterActivate['findings'] ?? []) !== 0) {
    fwrite(STDERR, json_encode($afterActivate, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    delement_antivirus_whitelist_remove_tree($moduleRoot);
    exit(1);
}

$manager->deleteRule((string)$fileSignatureRule['id']);
$rulesAfterDelete = $manager->listRules();

if (count($rulesAfterDelete) !== 1) {
    fwrite(STDERR, json_encode($rulesAfterDelete, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    delement_antivirus_whitelist_remove_tree($moduleRoot);
    exit(1);
}

$suppression = $manager->suppressFinding($result, $result['findings'][0], 0, 'smoke suppression');
$suppressions = $manager->listFindingSuppressions();

if (empty($suppression['fingerprint']) || count($suppressions) !== 1) {
    fwrite(STDERR, json_encode($suppressions, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    delement_antivirus_whitelist_remove_tree($moduleRoot);
    exit(1);
}

echo json_encode(
    [
        'partial_status' => $filtered['status'],
        'full_status' => $fullyFiltered['status'],
        'after_deactivate_status' => $afterDeactivate['status'],
        'after_activate_status' => $afterActivate['status'],
        'rules' => count($rulesAfterDelete),
        'finding_suppressions' => count($suppressions),
    ],
    JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
) . PHP_EOL;

delement_antivirus_whitelist_remove_tree($moduleRoot);
