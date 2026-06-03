<?php

use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\Scanner\Scanner;

require_once __DIR__ . '/../lib/Config/ScanConfig.php';
require_once __DIR__ . '/../lib/Detection/Severity.php';
require_once __DIR__ . '/../lib/Detection/Verdict.php';
require_once __DIR__ . '/../lib/Detection/Finding.php';
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

$fixtureRoot = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'delement_antivirus_external_signatures_smoke_' . getmypid();
$signaturesPath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'delement_antivirus_external_signatures_' . getmypid() . '.txt';

if (!is_dir($fixtureRoot) && !mkdir($fixtureRoot, 0777, true) && !is_dir($fixtureRoot)) {
    fwrite(STDERR, 'Cannot create fixture directory' . PHP_EOL);
    exit(1);
}

$fixtureFile = $fixtureRoot . DIRECTORY_SEPARATOR . 'fixture.txt';
file_put_contents($fixtureFile, 'DELEMENT_EXTERNAL_SIGNATURE_MARKER');
file_put_contents($signaturesPath, "/DELEMENT_EXTERNAL_SIGNATURE_MARKER/\n");

$config = new ScanConfig([
    'path' => $fixtureRoot,
    'profile' => ScanConfig::PROFILE_BALANCED,
    'action' => ScanConfig::ACTION_REPORT,
    'dry_run' => true,
    'signatures_path' => $signaturesPath,
    'exclude_paths' => [],
    'max_file_size_mb' => 1,
]);

$summary = (new Scanner())->scan($config)->toArray();

@unlink($fixtureFile);
@rmdir($fixtureRoot);
@unlink($signaturesPath);

$firstFinding = $summary['results'][0]['findings'][0] ?? [];

if (($firstFinding['signature_id'] ?? '') !== 'external_signature_1') {
    fwrite(STDERR, json_encode($summary, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    exit(1);
}

echo json_encode(
    [
        'status' => $summary['results'][0]['status'] ?? '',
        'signature_id' => $firstFinding['signature_id'],
        'category' => $firstFinding['category'] ?? '',
    ],
    JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
) . PHP_EOL;
