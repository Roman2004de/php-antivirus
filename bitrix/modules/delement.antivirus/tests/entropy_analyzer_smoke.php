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
require_once __DIR__ . '/../lib/Detection/Entropy/EntropyCalculator.php';
require_once __DIR__ . '/../lib/Detection/Entropy/EntropyFindingFactory.php';
require_once __DIR__ . '/../lib/Detection/Entropy/EntropyAnalyzer.php';
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

function delement_antivirus_entropy_remove_tree(string $path): void
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

function delement_antivirus_entropy_fail(string $message, array $context = []): void
{
    fwrite(STDERR, $message . PHP_EOL);

    if (!empty($context)) {
        fwrite(STDERR, json_encode($context, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    }

    exit(1);
}

function delement_antivirus_entropy_findings(array $result): array
{
    $findings = isset($result['findings']) && is_array($result['findings']) ? $result['findings'] : [];

    return array_values(array_filter($findings, static function (array $finding) {
        return (string)($finding['category'] ?? '') === 'entropy';
    }));
}

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'delement_antivirus_entropy_smoke_' . getmypid();
$documentRoot = $root . DIRECTORY_SEPARATOR . 'site';
$moduleRoot = $root . DIRECTORY_SEPARATOR . 'module';

delement_antivirus_entropy_remove_tree($root);

try {
    if (!mkdir($documentRoot, 0777, true) && !is_dir($documentRoot)) {
        delement_antivirus_entropy_fail('Cannot create document root');
    }

    if (!mkdir($moduleRoot . DIRECTORY_SEPARATOR . 'install', 0777, true) && !is_dir($moduleRoot . DIRECTORY_SEPARATOR . 'install')) {
        delement_antivirus_entropy_fail('Cannot create module root');
    }

    file_put_contents($moduleRoot . DIRECTORY_SEPARATOR . 'install' . DIRECTORY_SEPARATOR . 'version.php', "<?php\n\$arModuleVersion = ['VERSION' => '0.0.4'];\n");
    file_put_contents($moduleRoot . DIRECTORY_SEPARATOR . 'default_option.php', "<?php\n\$delement_antivirus_default_option = [];\n");

    $normalPath = $documentRoot . DIRECTORY_SEPARATOR . 'normal.php';
    $encodedPath = $documentRoot . DIRECTORY_SEPARATOR . 'encoded.php';
    $contextPath = $documentRoot . DIRECTORY_SEPARATOR . 'context.php';
    $cleanCliPath = $documentRoot . DIRECTORY_SEPARATOR . 'clean.php';
    $payload = base64_encode(random_bytes(480));
    $marker = 'ev' . 'al';

    file_put_contents($normalPath, "<?php\n\$title = 'regular Bitrix component template';\necho htmlspecialchars(\$title);\n");
    file_put_contents($encodedPath, "<?php\n\$payload = '" . $payload . "';\n");
    file_put_contents($contextPath, "<?php\n/* " . $marker . " */\n\$payload = '" . $payload . "';\n");
    file_put_contents($cleanCliPath, "<?php\n\$ok = true;\n");

    $scanner = new Scanner();
    $deepConfig = new ScanConfig([
        'document_root' => $documentRoot,
        'path' => $documentRoot,
        'scan_profile' => ScanConfig::SCAN_PROFILE_DEEP,
        'profile' => ScanConfig::PROFILE_BALANCED,
        'action' => ScanConfig::ACTION_REPORT,
        'dry_run' => true,
        'enable_entropy_analyzer' => 'N',
        'enable_entropy_in_deep_profile' => 'Y',
        'entropy_min_length' => 200,
        'entropy_threshold' => '4.7',
    ]);
    $disabledConfig = new ScanConfig([
        'document_root' => $documentRoot,
        'path' => $documentRoot,
        'scan_profile' => ScanConfig::SCAN_PROFILE_DEEP,
        'profile' => ScanConfig::PROFILE_BALANCED,
        'action' => ScanConfig::ACTION_REPORT,
        'dry_run' => true,
        'disable_entropy_analyzer' => 'Y',
        'enable_entropy_in_deep_profile' => 'Y',
        'entropy_min_length' => 200,
        'entropy_threshold' => '4.7',
    ]);

    $normal = $scanner->scanFile($normalPath, $deepConfig)->toArray();
    $encoded = $scanner->scanFile($encodedPath, $deepConfig)->toArray();
    $context = $scanner->scanFile($contextPath, $deepConfig)->toArray();
    $disabled = $scanner->scanFile($contextPath, $disabledConfig)->toArray();
    $normalEntropy = delement_antivirus_entropy_findings($normal);
    $encodedEntropy = delement_antivirus_entropy_findings($encoded);
    $contextEntropy = delement_antivirus_entropy_findings($context);
    $disabledEntropy = delement_antivirus_entropy_findings($disabled);

    if (!empty($normalEntropy)) {
        delement_antivirus_entropy_fail('Normal PHP code must not produce entropy findings', [
            'normal' => $normal,
        ]);
    }

    if (count($encodedEntropy) < 1) {
        delement_antivirus_entropy_fail('Long base64 payload was not detected by entropy analyzer', [
            'encoded' => $encoded,
        ]);
    }

    $contextFinding = $contextEntropy[0] ?? [];

    if (
        (string)($contextFinding['signature_id'] ?? '') !== 'entropy_high_encoded_payload'
        || (string)($contextFinding['severity'] ?? '') !== 'high'
        || (string)($contextFinding['confidence'] ?? '') !== 'medium'
        || (int)($contextFinding['score'] ?? 0) !== 7
        || (float)($contextFinding['entropy'] ?? 0) < 4.7
        || (int)($contextFinding['length'] ?? 0) < 200
        || !in_array('engine:entropy', $contextFinding['tags'] ?? [], true)
        || !in_array('risk:encoded_payload', $contextFinding['tags'] ?? [], true)
    ) {
        delement_antivirus_entropy_fail('Dangerous context entropy finding is wrong', [
            'context_finding' => $contextFinding,
            'context_result' => $context,
        ]);
    }

    if (!empty($disabledEntropy)) {
        delement_antivirus_entropy_fail('Disabled entropy analyzer must not produce findings', [
            'disabled' => $disabled,
        ]);
    }

    $_SERVER['DOCUMENT_ROOT'] = $documentRoot;
    $command = new ScanCommand($documentRoot, [
        'scan_path' => $cleanCliPath,
        'scan_profile' => ScanConfig::SCAN_PROFILE_STANDARD,
        'profile' => ScanConfig::PROFILE_BALANCED,
        'action' => ScanConfig::ACTION_REPORT,
        'dry_run' => 'Y',
        'quarantine_path' => $root . DIRECTORY_SEPARATOR . 'quarantine',
        'signatures_path' => '',
        'exclude_paths' => '',
        'batch_size' => '2',
        'max_file_size_mb' => '2',
        'enable_entropy_analyzer' => 'N',
        'enable_entropy_in_deep_profile' => 'Y',
        'entropy_min_length' => '200',
        'entropy_threshold' => '4.7',
        'entropy_context_window' => '300',
    ], $moduleRoot);
    $cli = $command->execute([
        'scan.php',
        '--path=' . $cleanCliPath,
        '--json',
        '--enable-entropy',
        '--entropy-threshold=4.5',
        '--entropy-min-length=120',
    ]);
    $payloadJson = json_decode((string)$cli['stdout'], true);

    if (
        ($cli['exit_code'] ?? null) !== ScanCommand::EXIT_OK
        || !is_array($payloadJson)
        || (($payloadJson['enable_entropy_analyzer'] ?? false) !== true)
        || ((int)($payloadJson['entropy_min_length'] ?? 0) !== 120)
        || abs((float)($payloadJson['entropy_threshold'] ?? 0) - 4.5) > 0.0001
    ) {
        delement_antivirus_entropy_fail('CLI entropy enable flags failed', [
            'cli' => $cli,
            'payload' => $payloadJson,
        ]);
    }

    $cliDisabled = $command->execute([
        'scan.php',
        '--path=' . $cleanCliPath,
        '--json',
        '--scan-profile=deep',
        '--disable-entropy',
    ]);
    $disabledPayload = json_decode((string)$cliDisabled['stdout'], true);

    if (
        ($cliDisabled['exit_code'] ?? null) !== ScanCommand::EXIT_OK
        || !is_array($disabledPayload)
        || (($disabledPayload['enable_entropy_analyzer'] ?? true) !== false)
    ) {
        delement_antivirus_entropy_fail('CLI entropy disable flag failed', [
            'cli' => $cliDisabled,
            'payload' => $disabledPayload,
        ]);
    }

    echo json_encode([
        'entropy_analyzer' => 'ok',
        'encoded_findings' => count($encodedEntropy),
        'context_severity' => $contextFinding['severity'],
        'context_confidence' => $contextFinding['confidence'],
        'cli_enable_entropy' => $payloadJson['enable_entropy_analyzer'],
        'cli_disable_entropy' => $disabledPayload['enable_entropy_analyzer'],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
} finally {
    delement_antivirus_entropy_remove_tree($root);
}
