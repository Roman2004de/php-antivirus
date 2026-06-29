<?php

use Delement\Antivirus\Cli\ScanCommand;
use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\Scanner\Scanner;

require_once __DIR__ . '/../lib/Storage/RuntimeDirectory.php';
require_once __DIR__ . '/../lib/Support/ModuleVersion.php';
require_once __DIR__ . '/../lib/Cli/ArgvParser.php';
require_once __DIR__ . '/../lib/Cli/ScanCommand.php';
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
require_once __DIR__ . '/../lib/Scanner/ScanResult.php';
require_once __DIR__ . '/../lib/Scanner/ScanSummary.php';
require_once __DIR__ . '/../lib/Scanner/Scanner.php';
require_once __DIR__ . '/../lib/Scanner/ScanActionApplier.php';
require_once __DIR__ . '/../lib/Scanner/ScanSessionStore.php';
require_once __DIR__ . '/../lib/Scanner/ScanRunService.php';
require_once __DIR__ . '/../lib/Quarantine/QuarantineManager.php';
require_once __DIR__ . '/../lib/Report/JsonReportWriter.php';
require_once __DIR__ . '/../lib/Report/ReportManager.php';
require_once __DIR__ . '/../lib/Whitelist/WhitelistManager.php';

function delement_antivirus_hash_db_remove_tree(string $path): void
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

function delement_antivirus_hash_db_fail(string $message, array $context = []): void
{
    fwrite(STDERR, $message . PHP_EOL);

    if (!empty($context)) {
        fwrite(STDERR, json_encode($context, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    }

    exit(1);
}

function delement_antivirus_hash_db_findings(array $result): array
{
    return isset($result['findings']) && is_array($result['findings']) ? $result['findings'] : [];
}

function delement_antivirus_hash_db_finding(array $result, string $signatureId): array
{
    foreach (delement_antivirus_hash_db_findings($result) as $finding) {
        if (is_array($finding) && (string)($finding['signature_id'] ?? '') === $signatureId) {
            return $finding;
        }
    }

    return [];
}

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'delement_antivirus_hash_db_smoke_' . getmypid();
$documentRoot = $root . DIRECTORY_SEPARATOR . 'site';
$moduleRoot = $root . DIRECTORY_SEPARATOR . 'module';

delement_antivirus_hash_db_remove_tree($root);

try {
    if (!mkdir($documentRoot, 0777, true) && !is_dir($documentRoot)) {
        delement_antivirus_hash_db_fail('Cannot create document root');
    }

    if (!mkdir($moduleRoot . DIRECTORY_SEPARATOR . 'install', 0777, true) && !is_dir($moduleRoot . DIRECTORY_SEPARATOR . 'install')) {
        delement_antivirus_hash_db_fail('Cannot create module root');
    }

    file_put_contents($moduleRoot . DIRECTORY_SEPARATOR . 'install' . DIRECTORY_SEPARATOR . 'version.php', "<?php\n\$arModuleVersion = ['VERSION' => '0.0.4'];\n");
    file_put_contents($moduleRoot . DIRECTORY_SEPARATOR . 'default_option.php', "<?php\n\$delement_antivirus_default_option = [];\n");

    $hitPath = $documentRoot . DIRECTORY_SEPARATOR . 'known.php';
    $prefixOnlyPath = $documentRoot . DIRECTORY_SEPARATOR . 'prefix_only.php';
    $cleanPath = $documentRoot . DIRECTORY_SEPARATOR . 'clean.php';

    file_put_contents($hitPath, "<?php\n\$fixture = 'known-hash-hit';\n");
    file_put_contents($prefixOnlyPath, "<?php\n\$fixture = 'prefix-only';\n");
    file_put_contents($cleanPath, "<?php\n\$fixture = 'clean';\n");

    $hitHash = hash_file('sha256', $hitPath);
    $prefixOnlyHash = hash_file('sha256', $prefixOnlyPath);
    $hashesPath = $root . DIRECTORY_SEPARATOR . 'malware_hashes.json';
    $prefixesPath = $root . DIRECTORY_SEPARATOR . 'malware_hash_prefixes.json';
    $prefixOnlyHashesPath = $root . DIRECTORY_SEPARATOR . 'prefix_only_hashes.json';
    $prefixOnlyPrefixesPath = $root . DIRECTORY_SEPARATOR . 'prefix_only_prefixes.json';
    $badHashesPath = $root . DIRECTORY_SEPARATOR . 'bad_hashes.json';

    file_put_contents($hashesPath, json_encode([
        'version' => '1',
        'algorithm' => 'sha256',
        'items' => [
            [
                'hash' => $hitHash,
                'name' => 'Synthetic Test WebShell',
                'severity' => 'critical',
                'tags' => ['webshell', 'known_malware'],
            ],
        ],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    file_put_contents($prefixesPath, json_encode([
        'version' => '1',
        'prefix_length' => 8,
        'prefixes' => [substr($hitHash, 0, 8)],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    file_put_contents($prefixOnlyHashesPath, json_encode([
        'version' => '1',
        'algorithm' => 'sha256',
        'items' => [
            [
                'hash' => $hitHash,
                'name' => 'Different Synthetic Hash',
                'severity' => 'critical',
                'tags' => ['known_malware'],
            ],
        ],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    file_put_contents($prefixOnlyPrefixesPath, json_encode([
        'version' => '1',
        'prefix_length' => 8,
        'prefixes' => [substr($prefixOnlyHash, 0, 8)],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    file_put_contents($badHashesPath, '{bad json');

    $scanner = new Scanner();
    $baseConfig = [
        'document_root' => $documentRoot,
        'path' => $documentRoot,
        'scan_profile' => ScanConfig::SCAN_PROFILE_STANDARD,
        'profile' => ScanConfig::PROFILE_BALANCED,
        'action' => ScanConfig::ACTION_REPORT,
        'dry_run' => true,
        'enable_hash_db' => 'Y',
        'malware_hashes_path' => $hashesPath,
        'malware_hash_prefixes_path' => $prefixesPath,
    ];
    $hit = $scanner->scanFile($hitPath, new ScanConfig($baseConfig))->toArray();
    $hitFinding = delement_antivirus_hash_db_finding($hit, 'known_malware_hash_match');

    if (
        empty($hitFinding)
        || (string)($hitFinding['severity'] ?? '') !== 'critical'
        || (int)($hitFinding['score'] ?? 0) !== 100
        || (string)($hitFinding['recommendation'] ?? '') !== 'quarantine'
        || (string)($hitFinding['hash'] ?? '') !== $hitHash
        || !in_array('engine:hash_db', $hitFinding['tags'] ?? [], true)
        || !in_array('risk:known_malware_hash', $hitFinding['tags'] ?? [], true)
    ) {
        delement_antivirus_hash_db_fail('Known malware hash finding is wrong', [
            'hit' => $hit,
            'hash' => $hitHash,
        ]);
    }

    $prefixOnly = $scanner->scanFile($prefixOnlyPath, new ScanConfig(array_merge($baseConfig, [
        'malware_hashes_path' => $prefixOnlyHashesPath,
        'malware_hash_prefixes_path' => $prefixOnlyPrefixesPath,
    ])))->toArray();

    if (!empty(delement_antivirus_hash_db_finding($prefixOnly, 'known_malware_hash_match'))) {
        delement_antivirus_hash_db_fail('Prefix-only match must not create malware finding', [
            'prefix_only' => $prefixOnly,
            'hash' => $prefixOnlyHash,
        ]);
    }

    $disabled = $scanner->scanFile($hitPath, new ScanConfig(array_merge($baseConfig, [
        'disable_hash_db' => 'Y',
    ])))->toArray();

    if (!empty(delement_antivirus_hash_db_finding($disabled, 'known_malware_hash_match'))) {
        delement_antivirus_hash_db_fail('Disabled hash database must not create finding', [
            'disabled' => $disabled,
        ]);
    }

    $badJsonSummary = $scanner->scan(new ScanConfig(array_merge($baseConfig, [
        'path' => $cleanPath,
        'malware_hashes_path' => $badHashesPath,
        'malware_hash_prefixes_path' => $prefixesPath,
    ])))->toArray();
    $badJsonFinding = isset($badJsonSummary['results'][0]) && is_array($badJsonSummary['results'][0])
        ? delement_antivirus_hash_db_finding($badJsonSummary['results'][0], 'hash_db_runtime_warning')
        : [];

    if (
        empty($badJsonFinding)
        || (int)($badJsonFinding['score'] ?? -1) !== 0
        || (int)($badJsonSummary['found_files'] ?? -1) !== 0
        || (int)($badJsonSummary['informational_findings_total'] ?? 0) < 1
    ) {
        delement_antivirus_hash_db_fail('Invalid hash database JSON must create informational runtime warning only', [
            'summary' => $badJsonSummary,
        ]);
    }

    $_SERVER['DOCUMENT_ROOT'] = $documentRoot;
    $command = new ScanCommand($documentRoot, [
        'scan_path' => $hitPath,
        'scan_profile' => ScanConfig::SCAN_PROFILE_STANDARD,
        'profile' => ScanConfig::PROFILE_BALANCED,
        'action' => ScanConfig::ACTION_REPORT,
        'dry_run' => 'Y',
        'quarantine_path' => $root . DIRECTORY_SEPARATOR . 'quarantine',
        'signatures_path' => '',
        'exclude_paths' => '',
        'batch_size' => '2',
        'max_file_size_mb' => '2',
        'enable_hash_db' => 'N',
        'malware_hashes_path' => '',
        'malware_hash_prefixes_path' => '',
    ], $moduleRoot);
    $cliDisabled = $command->execute([
        'scan.php',
        '--path=' . $hitPath,
        '--json',
        '--disable-hash-db',
        '--malware-hashes=' . $hashesPath,
        '--malware-hash-prefixes=' . $prefixesPath,
    ]);
    $disabledPayload = json_decode((string)$cliDisabled['stdout'], true);

    if (
        ($cliDisabled['exit_code'] ?? null) !== ScanCommand::EXIT_OK
        || !is_array($disabledPayload)
        || (($disabledPayload['enable_hash_db'] ?? true) !== false)
    ) {
        delement_antivirus_hash_db_fail('CLI --disable-hash-db failed', [
            'cli' => $cliDisabled,
            'payload' => $disabledPayload,
        ]);
    }

    $cliEnabled = $command->execute([
        'scan.php',
        '--path=' . $hitPath,
        '--json',
        '--enable-hash-db',
        '--malware-hashes=' . $hashesPath,
        '--malware-hash-prefixes=' . $prefixesPath,
    ]);
    $enabledPayload = json_decode((string)$cliEnabled['stdout'], true);

    if (
        ($cliEnabled['exit_code'] ?? null) !== ScanCommand::EXIT_FINDINGS
        || !is_array($enabledPayload)
        || (($enabledPayload['enable_hash_db'] ?? false) !== true)
        || (string)($enabledPayload['malware_hashes_path'] ?? '') !== $hashesPath
        || (string)($enabledPayload['malware_hash_prefixes_path'] ?? '') !== $prefixesPath
        || empty($enabledPayload['report_path'])
        || !is_file((string)$enabledPayload['report_path'])
    ) {
        delement_antivirus_hash_db_fail('CLI --enable-hash-db failed', [
            'cli' => $cliEnabled,
            'payload' => $enabledPayload,
        ]);
    }

    $cliReport = json_decode((string)file_get_contents((string)$enabledPayload['report_path']), true);
    $cliFindings = $cliReport['results'][0]['findings'] ?? [];
    $cliHashFinding = [];

    foreach ($cliFindings as $finding) {
        if (is_array($finding) && (string)($finding['signature_id'] ?? '') === 'known_malware_hash_match') {
            $cliHashFinding = $finding;
            break;
        }
    }

    if (empty($cliHashFinding)) {
        delement_antivirus_hash_db_fail('CLI report misses known malware hash finding', [
            'report' => $cliReport,
        ]);
    }

    echo json_encode([
        'hash_database' => 'ok',
        'hit_hash' => $hitHash,
        'severity' => $hitFinding['severity'],
        'score' => $hitFinding['score'],
        'prefix_only_findings' => count(delement_antivirus_hash_db_findings($prefixOnly)),
        'bad_json_warning' => $badJsonFinding['signature_id'],
        'cli_disable_hash_db' => $disabledPayload['enable_hash_db'],
        'cli_enable_hash_db' => $enabledPayload['enable_hash_db'],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
} finally {
    delement_antivirus_hash_db_remove_tree($root);
}
