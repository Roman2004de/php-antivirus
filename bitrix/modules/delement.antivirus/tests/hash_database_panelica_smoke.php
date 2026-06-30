<?php

use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\Detection\Hash\Import\PanelicaHashImporter;
use Delement\Antivirus\Scanner\Scanner;

require_once __DIR__ . '/../lib/Storage/RuntimeDirectory.php';
require_once __DIR__ . '/../lib/Config/ScanConfig.php';
require_once __DIR__ . '/../lib/File/FileTypeDetector.php';
require_once __DIR__ . '/../lib/File/FileReader.php';
require_once __DIR__ . '/../lib/File/FileFilter.php';
require_once __DIR__ . '/../lib/File/FileCollector.php';
require_once __DIR__ . '/../lib/Detection/Severity.php';
require_once __DIR__ . '/../lib/Detection/Verdict.php';
require_once __DIR__ . '/../lib/Detection/Finding.php';
require_once __DIR__ . '/../lib/Detection/SignatureLoader.php';
require_once __DIR__ . '/../lib/Detection/RuleEngine.php';
require_once __DIR__ . '/../lib/Detection/Detector.php';
require_once __DIR__ . '/../lib/Detection/Hash/HashDatabase.php';
require_once __DIR__ . '/../lib/Detection/Hash/HashPrefixIndex.php';
require_once __DIR__ . '/../lib/Detection/Hash/HashFindingFactory.php';
require_once __DIR__ . '/../lib/Detection/Hash/KnownMalwareHashAnalyzer.php';
require_once __DIR__ . '/../lib/Detection/Hash/Import/SignatureSourceMetadata.php';
require_once __DIR__ . '/../lib/Detection/Hash/Import/PanelicaImportResult.php';
require_once __DIR__ . '/../lib/Detection/Hash/Import/PanelicaHashNormalizer.php';
require_once __DIR__ . '/../lib/Detection/Hash/Import/PanelicaHashImporter.php';
require_once __DIR__ . '/../lib/Scanner/ScanResult.php';
require_once __DIR__ . '/../lib/Scanner/ScanSummary.php';
require_once __DIR__ . '/../lib/Scanner/Scanner.php';

function delement_antivirus_panelica_runtime_remove_tree(string $path): void
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

function delement_antivirus_panelica_runtime_fail(string $message, array $context = []): void
{
    fwrite(STDERR, $message . PHP_EOL);

    if (!empty($context)) {
        fwrite(STDERR, json_encode($context, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    }

    exit(1);
}

function delement_antivirus_panelica_runtime_finding(array $result, string $signatureId): array
{
    foreach ((array)($result['findings'] ?? []) as $finding) {
        if (is_array($finding) && (string)($finding['signature_id'] ?? '') === $signatureId) {
            return $finding;
        }
    }

    return [];
}

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'delement_antivirus_panelica_runtime_smoke_' . getmypid();
$documentRoot = $root . DIRECTORY_SEPARATOR . 'site';
$moduleRoot = $root . DIRECTORY_SEPARATOR . 'module';
$sourceRoot = $root . DIRECTORY_SEPARATOR . 'panelica';

delement_antivirus_panelica_runtime_remove_tree($root);

try {
    foreach ([
        $documentRoot,
        $moduleRoot,
        $sourceRoot . DIRECTORY_SEPARATOR . 'json',
    ] as $directory) {
        if (!mkdir($directory, 0777, true) && !is_dir($directory)) {
            delement_antivirus_panelica_runtime_fail('Cannot create fixture directory', ['directory' => $directory]);
        }
    }

    file_put_contents($sourceRoot . DIRECTORY_SEPARATOR . 'LICENSE', "MIT License\n\nPermission is hereby granted.\n");

    $hitPath = $documentRoot . DIRECTORY_SEPARATOR . 'panelica_hit.php';
    $prefixOnlyPath = $documentRoot . DIRECTORY_SEPARATOR . 'panelica_prefix_only.php';
    $cleanPath = $documentRoot . DIRECTORY_SEPARATOR . 'clean.php';
    file_put_contents($hitPath, "<?php\n\$fixture = 'panelica-hit';\n");
    file_put_contents($prefixOnlyPath, "<?php\n\$fixture = 'panelica-prefix-only';\n");
    file_put_contents($cleanPath, "<?php\n\$fixture = 'clean';\n");

    $hitHash = hash_file('sha256', $hitPath);
    $prefixOnlyHash = hash_file('sha256', $prefixOnlyPath);
    $hashesOutput = $root . DIRECTORY_SEPARATOR . 'db' . DIRECTORY_SEPARATOR . 'malware_hashes.json';
    $prefixesOutput = $root . DIRECTORY_SEPARATOR . 'db' . DIRECTORY_SEPARATOR . 'malware_hash_prefixes.json';

    file_put_contents($sourceRoot . DIRECTORY_SEPARATOR . 'json' . DIRECTORY_SEPARATOR . 'hashes.json', json_encode([
        'items' => [
            [
                'hash' => strtoupper($hitHash),
                'name' => 'Panelica Runtime Fixture',
                'family' => 'runtime_fixture',
                'category' => 'webshell',
                'severity' => 'low',
            ],
        ],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

    $import = (new PanelicaHashImporter($moduleRoot))->import($sourceRoot, [
        'hashes_output' => $hashesOutput,
        'prefixes_output' => $prefixesOutput,
    ]);

    if (!$import->isSuccess()) {
        delement_antivirus_panelica_runtime_fail('Panelica import for runtime failed', ['result' => $import->toArray()]);
    }

    $baseConfig = [
        'document_root' => $documentRoot,
        'path' => $documentRoot,
        'scan_profile' => ScanConfig::SCAN_PROFILE_STANDARD,
        'profile' => ScanConfig::PROFILE_BALANCED,
        'action' => ScanConfig::ACTION_REPORT,
        'dry_run' => true,
        'enable_hash_db' => 'Y',
        'malware_hashes_path' => $hashesOutput,
        'malware_hash_prefixes_path' => $prefixesOutput,
    ];

    $scanner = new Scanner();
    $hit = $scanner->scanFile($hitPath, new ScanConfig($baseConfig))->toArray();
    $hitFinding = delement_antivirus_panelica_runtime_finding($hit, 'known_malware_hash_match');

    if (
        empty($hitFinding)
        || (string)($hitFinding['severity'] ?? '') !== 'critical'
        || (int)($hitFinding['score'] ?? 0) !== 100
        || (string)($hitFinding['confidence'] ?? '') !== 'high'
        || (string)($hitFinding['recommendation'] ?? '') !== 'quarantine'
        || !in_array('engine:hash_db', (array)($hitFinding['tags'] ?? []), true)
        || !in_array('risk:known_malware_hash', (array)($hitFinding['tags'] ?? []), true)
        || !in_array('panelica', (array)($hitFinding['tags'] ?? []), true)
        || (string)($hitFinding['trace']['source'] ?? '') !== 'panelica'
        || (string)($hitFinding['trace']['family'] ?? '') !== 'runtime_fixture'
        || (string)($hitFinding['trace']['source_ref'] ?? '') !== 'json/hashes.json'
    ) {
        delement_antivirus_panelica_runtime_fail('Panelica runtime finding is wrong', [
            'hit' => $hit,
            'hash' => $hitHash,
        ]);
    }

    $prefixOnlyPrefixes = $root . DIRECTORY_SEPARATOR . 'db' . DIRECTORY_SEPARATOR . 'prefix_only_prefixes.json';
    $prefixDb = json_decode((string)file_get_contents($prefixesOutput), true);
    $prefixDb['prefixes'][] = substr($prefixOnlyHash, 0, 8);
    sort($prefixDb['prefixes'], SORT_STRING);
    file_put_contents($prefixOnlyPrefixes, json_encode($prefixDb, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

    $prefixOnly = (new Scanner())->scanFile($prefixOnlyPath, new ScanConfig(array_merge($baseConfig, [
        'malware_hash_prefixes_path' => $prefixOnlyPrefixes,
    ])))->toArray();

    if (!empty(delement_antivirus_panelica_runtime_finding($prefixOnly, 'known_malware_hash_match'))) {
        delement_antivirus_panelica_runtime_fail('Panelica prefix-only match must not create finding', [
            'prefix_only' => $prefixOnly,
            'hash' => $prefixOnlyHash,
        ]);
    }

    $missing = (new Scanner())->scanFile($cleanPath, new ScanConfig(array_merge($baseConfig, [
        'malware_hashes_path' => $root . DIRECTORY_SEPARATOR . 'missing_hashes.json',
        'malware_hash_prefixes_path' => $root . DIRECTORY_SEPARATOR . 'missing_prefixes.json',
    ])))->toArray();

    if (!empty(delement_antivirus_panelica_runtime_finding($missing, 'known_malware_hash_match'))) {
        delement_antivirus_panelica_runtime_fail('Missing Panelica database must not create finding', [
            'missing' => $missing,
        ]);
    }

    $badHashesPath = $root . DIRECTORY_SEPARATOR . 'db' . DIRECTORY_SEPARATOR . 'bad_hashes.json';
    file_put_contents($badHashesPath, '{bad json');
    $badJsonSummary = (new Scanner())->scan(new ScanConfig(array_merge($baseConfig, [
        'path' => $cleanPath,
        'malware_hashes_path' => $badHashesPath,
    ])))->toArray();
    $badJsonResult = $badJsonSummary['results'][0] ?? [];
    $badJsonFinding = is_array($badJsonResult)
        ? delement_antivirus_panelica_runtime_finding($badJsonResult, 'hash_db_runtime_warning')
        : [];

    if (
        empty($badJsonFinding)
        || (int)($badJsonFinding['score'] ?? -1) !== 0
        || (int)($badJsonSummary['found_files'] ?? -1) !== 0
    ) {
        delement_antivirus_panelica_runtime_fail('Bad Panelica hash database JSON must create runtime warning only', [
            'summary' => $badJsonSummary,
        ]);
    }

    echo json_encode([
        'hash_database_panelica' => 'ok',
        'hit_hash' => $hitHash,
        'source' => $hitFinding['trace']['source'],
        'severity' => $hitFinding['severity'],
        'score' => $hitFinding['score'],
        'prefix_only_findings' => count((array)($prefixOnly['findings'] ?? [])),
        'bad_json_warning' => $badJsonFinding['signature_id'],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
} finally {
    delement_antivirus_panelica_runtime_remove_tree($root);
}
