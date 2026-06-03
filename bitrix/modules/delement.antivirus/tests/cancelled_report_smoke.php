<?php

use Delement\Antivirus\Admin\AjaxController;
use Delement\Antivirus\Report\ReportManager;
use Delement\Antivirus\Scanner\ScanSessionStore;

require_once __DIR__ . '/../lib/Scanner/ScanSessionStore.php';
require_once __DIR__ . '/../lib/Report/ReportManager.php';
require_once __DIR__ . '/../lib/Admin/AjaxController.php';

class DelementAntivirusCancelledReportFakeStore extends ScanSessionStore
{
    public $session;
    public $saved = [];

    public function __construct()
    {
    }

    public function load(string $scanId): array
    {
        return $this->session;
    }

    public function save(array $session): void
    {
        $this->session = $session;
        $this->saved[] = $session;
    }
}

class DelementAntivirusCancelledReportFakeReportManager extends ReportManager
{
    public $savedSession;

    public function __construct()
    {
    }

    public function saveFromSession(array $session): string
    {
        $this->savedSession = $session;

        return '/tmp/delement_antivirus_cancelled_report.json';
    }
}

$store = new DelementAntivirusCancelledReportFakeStore();
$store->session = [
    'scan_id' => 'cancelled_smoke',
    'status' => 'running',
    'started_at' => date('c'),
    'finished_at' => null,
    'created_by' => 1,
    'config' => [
        'path' => __DIR__,
        'profile' => 'balanced',
        'action' => 'report',
        'dry_run' => true,
    ],
    'files' => ['one.php', 'two.php', 'three.php'],
    'cursor' => 2,
    'processed_files' => 2,
    'total_files_estimated' => 3,
    'found_total' => 1,
    'runtime_errors' => 0,
    'current_file' => 'two.php',
    'results' => [
        [
            'file_path' => 'one.php',
            'status' => 'clean',
            'findings' => [],
        ],
        [
            'file_path' => 'two.php',
            'status' => 'malicious',
            'findings' => [
                ['signature_id' => 'smoke'],
            ],
        ],
    ],
    'report_path' => '',
];

$reportManager = new DelementAntivirusCancelledReportFakeReportManager();
$controller = new AjaxController('delement.antivirus', __DIR__, $store, $reportManager);
$response = $controller->handle('cancel_scan', ['scan_id' => 'cancelled_smoke'], 1);

if (
    ($response['status'] ?? '') !== 'cancelled'
    || ($response['report_path'] ?? '') === ''
    || !is_array($reportManager->savedSession)
    || ($reportManager->savedSession['status'] ?? '') !== 'cancelled'
    || ($reportManager->savedSession['processed_files'] ?? 0) !== 2
) {
    fwrite(STDERR, json_encode(['response' => $response, 'saved_session' => $reportManager->savedSession], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    exit(1);
}

echo json_encode(
    [
        'status' => $response['status'],
        'processed_files' => $response['processed_files'],
        'report_path' => $response['report_path'],
    ],
    JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
) . PHP_EOL;
