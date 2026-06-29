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
require_once __DIR__ . '/../lib/Detection/Url/UrlExtractor.php';
require_once __DIR__ . '/../lib/Detection/Url/SuspiciousDomainList.php';
require_once __DIR__ . '/../lib/Detection/Url/UrlFindingFactory.php';
require_once __DIR__ . '/../lib/Detection/Url/UrlAnalyzer.php';
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

function delement_antivirus_url_remove_tree(string $path): void
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

function delement_antivirus_url_fail(string $message, array $context = []): void
{
    fwrite(STDERR, $message . PHP_EOL);

    if (!empty($context)) {
        fwrite(STDERR, json_encode($context, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    }

    exit(1);
}

function delement_antivirus_url_signatures(array $result): array
{
    $signatures = [];

    foreach (($result['findings'] ?? []) as $finding) {
        if (is_array($finding) && (string)($finding['category'] ?? '') === 'url') {
            $signatures[] = (string)($finding['signature_id'] ?? '');
        }
    }

    sort($signatures, SORT_STRING);

    return $signatures;
}

function delement_antivirus_url_finding(array $result, string $signatureId): array
{
    foreach (($result['findings'] ?? []) as $finding) {
        if (is_array($finding) && (string)($finding['signature_id'] ?? '') === $signatureId) {
            return $finding;
        }
    }

    return [];
}

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'delement_antivirus_url_smoke_' . getmypid();
$documentRoot = $root . DIRECTORY_SEPARATOR . 'site';
$moduleRoot = $root . DIRECTORY_SEPARATOR . 'module';
$domainListPath = $root . DIRECTORY_SEPARATOR . 'suspicious_domains.json';
$badDomainListPath = $root . DIRECTORY_SEPARATOR . 'broken_domains.json';

delement_antivirus_url_remove_tree($root);

try {
    if (!mkdir($documentRoot, 0777, true) && !is_dir($documentRoot)) {
        delement_antivirus_url_fail('Cannot create document root');
    }

    if (!mkdir($moduleRoot . DIRECTORY_SEPARATOR . 'install', 0777, true) && !is_dir($moduleRoot . DIRECTORY_SEPARATOR . 'install')) {
        delement_antivirus_url_fail('Cannot create module root');
    }

    file_put_contents($moduleRoot . DIRECTORY_SEPARATOR . 'install' . DIRECTORY_SEPARATOR . 'version.php', "<?php\n\$arModuleVersion = ['VERSION' => '0.0.4'];\n");
    file_put_contents($moduleRoot . DIRECTORY_SEPARATOR . 'default_option.php', "<?php\n\$delement_antivirus_default_option = [];\n");
    file_put_contents($domainListPath, json_encode([
        'version' => '1',
        'items' => [
            [
                'domain' => 'example-malicious.test',
                'severity' => 'critical',
                'tags' => ['malware', 'payload_host'],
            ],
        ],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    file_put_contents($badDomainListPath, '{broken json');

    $phpPath = $documentRoot . DIRECTORY_SEPARATOR . 'loader.php';
    $jsPath = $documentRoot . DIRECTORY_SEPARATOR . 'inject.js';
    $htaccessPath = $documentRoot . DIRECTORY_SEPARATOR . '.htaccess';
    $iframePath = $documentRoot . DIRECTORY_SEPARATOR . 'frame.html';
    $cleanPath = $documentRoot . DIRECTORY_SEPARATOR . 'clean.php';
    $infoRoot = $root . DIRECTORY_SEPARATOR . 'info_only';
    $infoPath = $infoRoot . DIRECTORY_SEPARATOR . 'link.html';

    file_put_contents($phpPath, "<?php\n\$payload = file_get_contents('https://cdn.safe.test/payload.txt');\n");
    file_put_contents($jsPath, "document.write('<script src=\"https://cdn.safe.test/app.js\"></script>');\n");
    file_put_contents($htaccessPath, "RewriteRule ^(.*)$ https://redirect.safe.test/\$1 [R=302,L]\n");
    file_put_contents($iframePath, "<iframe src=\"https://example-malicious.test/frame.html\"></iframe>\n");
    file_put_contents($cleanPath, "<?php\n\$ok = true;\n");
    mkdir($infoRoot, 0777, true);
    file_put_contents($infoPath, "<a href=\"https://docs.safe.test/manual.html\">manual</a>\n");

    $config = new ScanConfig([
        'document_root' => $documentRoot,
        'path' => $documentRoot,
        'scan_profile' => ScanConfig::SCAN_PROFILE_STANDARD,
        'profile' => ScanConfig::PROFILE_BALANCED,
        'action' => ScanConfig::ACTION_REPORT,
        'dry_run' => true,
        'enable_url_analyzer' => 'Y',
        'suspicious_domains_path' => $domainListPath,
    ]);
    $scanner = new Scanner();
    $php = $scanner->scanFile($phpPath, $config)->toArray();
    $js = $scanner->scanFile($jsPath, $config)->toArray();
    $htaccess = $scanner->scanFile($htaccessPath, $config)->toArray();
    $iframe = $scanner->scanFile($iframePath, $config)->toArray();

    foreach ([
        'php' => [$php, 'remote_payload_loader'],
        'js' => [$js, 'external_script_injection'],
        'htaccess' => [$htaccess, 'htaccess_external_redirect'],
        'iframe' => [$iframe, 'suspicious_iframe_url'],
    ] as $name => $expectation) {
        [$result, $signature] = $expectation;
        $signatures = delement_antivirus_url_signatures($result);

        if (!in_array('external_url_detected', $signatures, true) || !in_array($signature, $signatures, true)) {
            delement_antivirus_url_fail('URL signatures are missing for ' . $name, [
                'expected' => ['external_url_detected', $signature],
                'signatures' => $signatures,
                'result' => $result,
            ]);
        }
    }

    $domainFinding = delement_antivirus_url_finding($iframe, 'suspicious_domain_match');

    if (
        (string)($domainFinding['severity'] ?? '') !== 'critical'
        || (int)($domainFinding['score'] ?? 0) !== 10
        || (string)($domainFinding['domain'] ?? '') !== 'example-malicious.test'
        || !in_array('engine:url', $domainFinding['tags'] ?? [], true)
        || !in_array('risk:remote_loader', $domainFinding['tags'] ?? [], true)
        || (($domainFinding['trace']['matched_domain'] ?? '') !== 'example-malicious.test')
    ) {
        delement_antivirus_url_fail('Suspicious domain match is wrong', [
            'finding' => $domainFinding,
            'iframe' => $iframe,
        ]);
    }

    $disabled = $scanner->scanFile($phpPath, new ScanConfig([
        'document_root' => $documentRoot,
        'path' => $documentRoot,
        'scan_profile' => ScanConfig::SCAN_PROFILE_STANDARD,
        'profile' => ScanConfig::PROFILE_BALANCED,
        'action' => ScanConfig::ACTION_REPORT,
        'dry_run' => true,
        'disable_url_analyzer' => 'Y',
        'enable_url_analyzer' => 'Y',
        'suspicious_domains_path' => $domainListPath,
    ]))->toArray();

    if (!empty(delement_antivirus_url_signatures($disabled))) {
        delement_antivirus_url_fail('Disabled URL analyzer must not produce URL findings', [
            'disabled' => $disabled,
        ]);
    }

    $infoSummary = $scanner->scan(new ScanConfig([
        'document_root' => $infoRoot,
        'path' => $infoRoot,
        'scan_profile' => ScanConfig::SCAN_PROFILE_STANDARD,
        'profile' => ScanConfig::PROFILE_BALANCED,
        'action' => ScanConfig::ACTION_REPORT,
        'dry_run' => true,
        'enable_url_analyzer' => 'Y',
        'suspicious_domains_path' => $domainListPath,
    ]))->toArray();

    if (
        (int)($infoSummary['found_files'] ?? -1) !== 0
        || (int)($infoSummary['informational_findings_total'] ?? 0) !== 1
        || empty($infoSummary['results'][0]['findings'])
        || (int)($infoSummary['results'][0]['findings'][0]['score'] ?? -1) !== 0
    ) {
        delement_antivirus_url_fail('Info-only external URL must not increment found_files', [
            'summary' => $infoSummary,
        ]);
    }

    $badJson = $scanner->scanFile($iframePath, new ScanConfig([
        'document_root' => $documentRoot,
        'path' => $documentRoot,
        'scan_profile' => ScanConfig::SCAN_PROFILE_STANDARD,
        'profile' => ScanConfig::PROFILE_BALANCED,
        'action' => ScanConfig::ACTION_REPORT,
        'dry_run' => true,
        'enable_url_analyzer' => 'Y',
        'suspicious_domains_path' => $badDomainListPath,
    ]))->toArray();

    if (in_array('suspicious_domain_match', delement_antivirus_url_signatures($badJson), true)) {
        delement_antivirus_url_fail('Invalid suspicious domain JSON must be ignored safely', [
            'bad_json_result' => $badJson,
        ]);
    }

    $_SERVER['DOCUMENT_ROOT'] = $documentRoot;
    $command = new ScanCommand($documentRoot, [
        'scan_path' => $cleanPath,
        'scan_profile' => ScanConfig::SCAN_PROFILE_STANDARD,
        'profile' => ScanConfig::PROFILE_BALANCED,
        'action' => ScanConfig::ACTION_REPORT,
        'dry_run' => 'Y',
        'quarantine_path' => $root . DIRECTORY_SEPARATOR . 'quarantine',
        'signatures_path' => '',
        'exclude_paths' => '',
        'batch_size' => '2',
        'max_file_size_mb' => '2',
        'enable_url_analyzer' => 'Y',
        'suspicious_domains_path' => $domainListPath,
    ], $moduleRoot);
    $cliDisabled = $command->execute([
        'scan.php',
        '--path=' . $cleanPath,
        '--json',
        '--disable-url-analyzer',
        '--suspicious-domains=' . $domainListPath,
    ]);
    $payload = json_decode((string)$cliDisabled['stdout'], true);

    if (
        ($cliDisabled['exit_code'] ?? null) !== ScanCommand::EXIT_OK
        || !is_array($payload)
        || (($payload['enable_url_analyzer'] ?? true) !== false)
        || (string)($payload['suspicious_domains_path'] ?? '') !== $domainListPath
    ) {
        delement_antivirus_url_fail('CLI URL analyzer flags failed', [
            'cli' => $cliDisabled,
            'payload' => $payload,
        ]);
    }

    echo json_encode([
        'url_extractor' => 'ok',
        'php' => delement_antivirus_url_signatures($php),
        'js' => delement_antivirus_url_signatures($js),
        'htaccess' => delement_antivirus_url_signatures($htaccess),
        'suspicious_domain_severity' => $domainFinding['severity'],
        'info_only_found_files' => $infoSummary['found_files'],
        'informational_findings_total' => $infoSummary['informational_findings_total'],
        'cli_enable_url_analyzer' => $payload['enable_url_analyzer'],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
} finally {
    delement_antivirus_url_remove_tree($root);
}
