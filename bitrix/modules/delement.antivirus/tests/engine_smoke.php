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

$fixtureRoot = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'delement_antivirus_engine_smoke_' . getmypid();
$uploadDir = $fixtureRoot . DIRECTORY_SEPARATOR . 'upload';

if (!is_dir($uploadDir) && !mkdir($uploadDir, 0777, true) && !is_dir($uploadDir)) {
    fwrite(STDERR, 'Cannot create fixture directory' . PHP_EOL);
    exit(1);
}

$fixtureFile = $uploadDir . DIRECTORY_SEPARATOR . 'shell.php';
file_put_contents($fixtureFile, '<?php echo "fixture";');

$config = new ScanConfig([
    'path' => $fixtureRoot,
    'profile' => ScanConfig::PROFILE_BALANCED,
    'action' => ScanConfig::ACTION_REPORT,
    'dry_run' => true,
    'exclude_paths' => [],
    'max_file_size_mb' => 1,
]);

$summary = (new Scanner())->scan($config)->toArray();

@unlink($fixtureFile);
@rmdir($uploadDir);
@rmdir($fixtureRoot);

if ($summary['found_files'] < 1 || empty($summary['results'][0]['findings'])) {
    fwrite(STDERR, json_encode($summary, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    exit(1);
}

echo json_encode($summary, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
