<?php

use Delement\Antivirus\Detection\Finding;
use Delement\Antivirus\Detection\Severity;
use Delement\Antivirus\Scanner\ScanResult;
use Delement\Antivirus\Storage\RuntimeDirectory;
use Delement\Antivirus\Whitelist\WhitelistManager;

require_once __DIR__ . '/../lib/Storage/RuntimeDirectory.php';
require_once __DIR__ . '/../lib/Detection/Severity.php';
require_once __DIR__ . '/../lib/Detection/Verdict.php';
require_once __DIR__ . '/../lib/Detection/Finding.php';
require_once __DIR__ . '/../lib/Whitelist/SuppressionFingerprint.php';
require_once __DIR__ . '/../lib/Whitelist/SuppressionStore.php';
require_once __DIR__ . '/../lib/Whitelist/FindingSuppressor.php';
require_once __DIR__ . '/../lib/Whitelist/WhitelistManager.php';
require_once __DIR__ . '/../lib/Scanner/ScanResult.php';

function delement_antivirus_finding_suppressor_remove_tree(string $path): void
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

function delement_antivirus_finding_suppressor_fail(string $message, array $context = []): void
{
    fwrite(STDERR, $message . PHP_EOL);

    if (!empty($context)) {
        fwrite(STDERR, json_encode($context, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    }

    exit(1);
}

$moduleRoot = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'delement_antivirus_finding_suppressor_smoke_' . getmypid();
$documentRootA = $moduleRoot . DIRECTORY_SEPARATOR . 'site_a';
$documentRootB = $moduleRoot . DIRECTORY_SEPARATOR . 'site_b';
$relativePath = 'local/php_interface/init.php';
$filePathA = $documentRootA . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relativePath);
$filePathB = $documentRootB . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relativePath);
$thresholds = ['suspicious' => 4, 'malicious' => 8];

delement_antivirus_finding_suppressor_remove_tree($moduleRoot);

try {
    if (!mkdir(dirname($filePathA), 0777, true) && !is_dir(dirname($filePathA))) {
        delement_antivirus_finding_suppressor_fail('Cannot create fixture directory A');
    }

    if (!mkdir(dirname($filePathB), 0777, true) && !is_dir(dirname($filePathB))) {
        delement_antivirus_finding_suppressor_fail('Cannot create fixture directory B');
    }

    file_put_contents($filePathA, "<?php\n");
    file_put_contents($filePathB, "<?php\n");

    $resultA = [
        'file_path' => $filePathA,
        'file_hash' => hash('sha256', 'fixture-a'),
        'normalized_hash' => hash('sha256', 'fixture'),
        'status' => 'malicious',
        'score' => 13,
        'severity' => Severity::HIGH,
        'findings' => [
            [
                'signature_id' => 'php_eval',
                'category' => 'php_code_execution',
                'severity' => Severity::HIGH,
                'score' => 8,
                'target' => 'content',
                'excerpt' => 'primary suspicious fragment',
            ],
            [
                'signature_id' => 'php_shell_exec',
                'category' => 'php_code_execution',
                'severity' => Severity::HIGH,
                'score' => 5,
                'target' => 'content',
                'excerpt' => 'secondary suspicious fragment',
            ],
        ],
    ];
    $resultB = $resultA;
    $resultB['file_path'] = $filePathB;
    $resultB['file_hash'] = hash('sha256', 'fixture-b');

    $managerA = new WhitelistManager($moduleRoot, null, $documentRootA);
    $preparedA = $managerA->filterResult($resultA, $thresholds);
    $primaryFinding = $preparedA['findings'][0] ?? [];
    $secondaryFinding = $preparedA['findings'][1] ?? [];

    if (
        !is_array($primaryFinding)
        || !preg_match('/^[a-f0-9]{64}$/', (string)($primaryFinding['fingerprint'] ?? ''))
        || !preg_match('/^[a-f0-9]{64}$/', (string)($secondaryFinding['fingerprint'] ?? ''))
    ) {
        delement_antivirus_finding_suppressor_fail('Finding fingerprints were not calculated', [
            'prepared' => $preparedA,
        ]);
    }

    $suppression = $managerA->suppressFinding($preparedA, $primaryFinding, 7, 'Known safe custom loader');
    $filteredA = $managerA->filterResult($resultA, $thresholds);

    if (
        count($filteredA['findings'] ?? []) !== 1
        || (($filteredA['findings'][0]['signature_id'] ?? '') !== 'php_shell_exec')
        || (($filteredA['score'] ?? 0) !== 5)
        || (($filteredA['status'] ?? '') !== 'suspicious')
        || (($filteredA['suppressed_total'] ?? 0) !== 1)
        || (($filteredA['suppressed_findings'][0]['signature_id'] ?? '') !== 'php_eval')
    ) {
        delement_antivirus_finding_suppressor_fail('Suppressing one finding changed the wrong scope', [
            'suppression' => $suppression,
            'filtered' => $filteredA,
        ]);
    }

    $managerB = new WhitelistManager($moduleRoot, null, $documentRootB);
    $filteredB = $managerB->filterResult($resultB, $thresholds);

    if (
        count($filteredB['findings'] ?? []) !== 1
        || (($filteredB['findings'][0]['signature_id'] ?? '') !== 'php_shell_exec')
    ) {
        delement_antivirus_finding_suppressor_fail('Suppression fingerprint is not stable across document roots', [
            'filtered' => $filteredB,
        ]);
    }

    $scanResult = ScanResult::fromFindings(
        $filePathA,
        'malicious',
        13,
        Severity::HIGH,
        [
            new Finding($resultA['findings'][0]),
            new Finding($resultA['findings'][1]),
        ],
        'report',
        true,
        [],
        null,
        $documentRootA
    )->toArray();

    foreach ($scanResult['findings'] as $finding) {
        if (!preg_match('/^[a-f0-9]{64}$/', (string)($finding['fingerprint'] ?? ''))) {
            delement_antivirus_finding_suppressor_fail('ScanResult finding misses fingerprint', [
                'scan_result' => $scanResult,
            ]);
        }
    }

    $whitelistPath = RuntimeDirectory::resolve($moduleRoot, 'whitelist');
    file_put_contents($whitelistPath . DIRECTORY_SEPARATOR . 'finding_suppressions.json', '{broken json');
    $badJsonManager = new WhitelistManager($moduleRoot, null, $documentRootA);
    $badJsonFiltered = $badJsonManager->filterResult($resultA, $thresholds);

    if (count($badJsonFiltered['findings'] ?? []) !== 2) {
        delement_antivirus_finding_suppressor_fail('Broken suppressions JSON must not suppress or fatal', [
            'filtered' => $badJsonFiltered,
        ]);
    }

    echo json_encode([
        'finding_suppressor' => 'ok',
        'suppressed_signature' => $filteredA['suppressed_findings'][0]['signature_id'],
        'remaining_signature' => $filteredA['findings'][0]['signature_id'],
        'score_after_suppress' => $filteredA['score'],
        'stable_across_document_roots' => true,
        'bad_json_findings_count' => count($badJsonFiltered['findings']),
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
} finally {
    delement_antivirus_finding_suppressor_remove_tree($moduleRoot);
}
