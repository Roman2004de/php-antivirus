<?php

use Delement\Antivirus\Report\JsonReportWriter;
use Delement\Antivirus\Report\ReportManager;

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
                ],
            ],
        ],
    ],
];

$path = $manager->saveFromSession($session);
$loaded = $manager->load($session['scan_id']);
$reports = $manager->listReports();

@unlink($path);
@rmdir($reportsPath);
@rmdir(dirname($reportsPath));
@rmdir($moduleRoot);

if (($loaded['summary']['findings_total'] ?? 0) !== 1 || count($reports) !== 1) {
    fwrite(STDERR, json_encode(['loaded' => $loaded, 'reports' => $reports], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    exit(1);
}

echo json_encode($loaded['summary'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
