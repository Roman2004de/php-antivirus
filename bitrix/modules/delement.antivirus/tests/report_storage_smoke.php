<?php

use Delement\Antivirus\Report\JsonReportWriter;
use Delement\Antivirus\Report\ReportManager;

require_once __DIR__ . '/../lib/Storage/RuntimeDirectory.php';
require_once __DIR__ . '/../lib/Detection/Tags/TagCatalog.php';
require_once __DIR__ . '/../lib/Detection/Tags/PathTagger.php';
require_once __DIR__ . '/../lib/Detection/Tags/FindingTagger.php';
require_once __DIR__ . '/../lib/Detection/Tags/ResultTagger.php';
require_once __DIR__ . '/../lib/Report/JsonReportWriter.php';
require_once __DIR__ . '/../lib/Report/ReportManager.php';

$moduleRoot = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'delement_antivirus_report_smoke_' . getmypid();
$reportsPath = $moduleRoot . DIRECTORY_SEPARATOR . 'var' . DIRECTORY_SEPARATOR . 'reports';

if (!is_dir($reportsPath) && !mkdir($reportsPath, 0777, true) && !is_dir($reportsPath)) {
    fwrite(STDERR, 'Cannot create report directory' . PHP_EOL);
    exit(1);
}

$manager = new ReportManager($moduleRoot);
$session = [
    'scan_id' => 'smoke_' . getmypid(),
    'status' => 'finished',
    'started_at' => date('c'),
    'finished_at' => date('c'),
    'config' => [
        'path' => $moduleRoot,
        'profile' => 'balanced',
        'action' => 'report',
        'dry_run' => true,
    ],
    'processed_files' => 1,
    'total_files_estimated' => 1,
    'found_total' => 1,
    'runtime_errors' => 0,
    'results' => [
        [
            'file_path' => $moduleRoot . DIRECTORY_SEPARATOR . 'upload' . DIRECTORY_SEPARATOR . 'shell.php',
            'status' => 'malicious',
            'score' => 8,
            'severity' => 'high',
            'findings' => [
                [
                    'signature_id' => 'bitrix_php_in_upload',
                    'category' => 'bitrix_specific',
                    'severity' => 'high',
                    'score' => 8,
                    'excerpt' => '',
                    'rule_type' => 'path',
                ],
            ],
        ],
    ],
];

$path = $manager->saveFromSession($session);
$loaded = $manager->load($session['scan_id']);
$reports = $manager->listReports();
$deleted = $manager->deleteReport($session['scan_id']);
$reportsAfterDelete = $manager->listReports();

@unlink($reportsPath . DIRECTORY_SEPARATOR . '.htaccess');
@unlink($reportsPath . DIRECTORY_SEPARATOR . 'index.php');
@rmdir($reportsPath);
@unlink(dirname($reportsPath) . DIRECTORY_SEPARATOR . '.htaccess');
@unlink(dirname($reportsPath) . DIRECTORY_SEPARATOR . 'index.php');
@rmdir(dirname($reportsPath));
@rmdir($moduleRoot);

if (
    ($loaded['summary']['findings_total'] ?? 0) !== 1
    || empty($loaded['summary']['tags'])
    || empty($loaded['results'][0]['tags'])
    || empty($loaded['results'][0]['findings'][0]['tags'])
    || count($reports) !== 1
    || !$deleted
    || count($reportsAfterDelete) !== 0
) {
    fwrite(STDERR, json_encode([
        'loaded' => $loaded,
        'reports' => $reports,
        'deleted' => $deleted,
        'reports_after_delete' => $reportsAfterDelete,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    exit(1);
}

echo json_encode($loaded['summary'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
