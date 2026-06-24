<?php

use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\Scanner\Scanner;

require_once __DIR__ . '/../lib/Config/ScanConfig.php';
require_once __DIR__ . '/../lib/Detection/Severity.php';
require_once __DIR__ . '/../lib/Detection/Verdict.php';
require_once __DIR__ . '/../lib/Detection/Finding.php';
require_once __DIR__ . '/../lib/Detection/Htaccess/HtaccessRule.php';
require_once __DIR__ . '/../lib/Detection/Htaccess/HtaccessFindingFactory.php';
require_once __DIR__ . '/../lib/Detection/Htaccess/HtaccessAnalyzer.php';
require_once __DIR__ . '/../lib/Detection/SignatureLoader.php';
require_once __DIR__ . '/../lib/Detection/RuleEngine.php';
require_once __DIR__ . '/../lib/Detection/Detector.php';
require_once __DIR__ . '/../lib/File/FileTypeDetector.php';
require_once __DIR__ . '/../lib/File/FileReader.php';
require_once __DIR__ . '/../lib/File/FileFilter.php';
require_once __DIR__ . '/../lib/File/FileCollector.php';
require_once __DIR__ . '/../lib/Scanner/ScanResult.php';
require_once __DIR__ . '/../lib/Scanner/ScanSummary.php';
require_once __DIR__ . '/../lib/Scanner/Scanner.php';

function delement_antivirus_htaccess_smoke_remove_tree(string $path): void
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

function delement_antivirus_htaccess_smoke_fail(string $message, array $context = []): void
{
    fwrite(STDERR, $message . PHP_EOL);

    if (!empty($context)) {
        fwrite(STDERR, json_encode($context, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    }

    exit(1);
}

$fixtureRoot = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'delement_antivirus_htaccess_smoke_' . getmypid();
delement_antivirus_htaccess_smoke_remove_tree($fixtureRoot);

try {
    $uploadPath = $fixtureRoot . DIRECTORY_SEPARATOR . 'upload';

    if (!mkdir($uploadPath, 0777, true) && !is_dir($uploadPath)) {
        delement_antivirus_htaccess_smoke_fail('Cannot create fixture directory');
    }

    file_put_contents($fixtureRoot . DIRECTORY_SEPARATOR . '.htaccess', implode("\n", [
        'AddHandler application/x-httpd-php .jpg',
        'php_value auto_prepend_file /upload/shell.php',
        'RewriteRule ^.*$ wp-login.php [L]',
        '<?php eval(base64_decode($x));',
    ]));
    file_put_contents($uploadPath . DIRECTORY_SEPARATOR . '.htaccess', implode("\n", [
        '<FilesMatch ".+\\.php$">',
        'Require all granted',
        '</FilesMatch>',
    ]));

    $config = new ScanConfig([
        'path' => $fixtureRoot,
        'scan_profile' => ScanConfig::SCAN_PROFILE_DEEP,
        'profile' => ScanConfig::PROFILE_BALANCED,
        'action' => ScanConfig::ACTION_REPORT,
        'dry_run' => true,
        'exclude_paths' => [],
        'max_file_size_mb' => 1,
    ]);
    $summary = (new Scanner())->scan($config)->toArray();
    $signatures = [];

    foreach ($summary['results'] as $result) {
        foreach ($result['findings'] as $finding) {
            $id = (string)($finding['signature_id'] ?? '');

            if (strpos($id, 'htaccess_') === 0) {
                $signatures[$id] = $finding;
            }
        }
    }

    $expected = [
        'htaccess_php_handler_for_static_ext',
        'htaccess_auto_prepend_append',
        'htaccess_embedded_code',
        'htaccess_suspicious_rewrite',
        'htaccess_foreign_cms_marker',
        'htaccess_access_bypass',
    ];
    $missing = [];

    foreach ($expected as $signatureId) {
        if (empty($signatures[$signatureId])) {
            $missing[] = $signatureId;
        }
    }

    if (!empty($missing)) {
        delement_antivirus_htaccess_smoke_fail('Htaccess findings are missing', [
            'missing' => $missing,
            'signatures' => array_keys($signatures),
            'summary' => $summary,
        ]);
    }

    echo json_encode([
        'htaccess' => 'ok',
        'signatures' => array_keys($signatures),
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
} finally {
    delement_antivirus_htaccess_smoke_remove_tree($fixtureRoot);
}
