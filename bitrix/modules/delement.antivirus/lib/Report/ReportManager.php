<?php

namespace Delement\Antivirus\Report;

use Delement\Antivirus\Storage\RuntimeDirectory;
use RuntimeException;

class ReportManager
{
    private $reportsPath;
    private $writer;

    public function __construct(string $moduleRoot = null, JsonReportWriter $writer = null)
    {
        $moduleRoot = $moduleRoot ?: dirname(__DIR__, 2);
        $this->reportsPath = RuntimeDirectory::resolve($moduleRoot, 'reports');
        $this->writer = $writer ?: new JsonReportWriter();
    }

    public function saveFromSession(array $session): string
    {
        if (empty($session['scan_id'])) {
            throw new RuntimeException('Scan session id is empty');
        }

        $scanId = (string)$session['scan_id'];
        $report = $this->buildReport($session);
        $path = $this->getReportPath($scanId);

        $this->writer->write($path, $report);

        return $path;
    }

    public function load(string $scanId): array
    {
        return $this->writer->read($this->getReportPath($scanId));
    }

    public function listReports(int $limit = 50): array
    {
        if (!is_dir($this->reportsPath)) {
            return [];
        }

        $files = glob($this->reportsPath . '/*.json');

        if (!is_array($files)) {
            return [];
        }

        usort($files, static function ($left, $right) {
            return filemtime($right) <=> filemtime($left);
        });

        $reports = [];

        foreach (array_slice($files, 0, $limit) as $file) {
            try {
                $report = $this->writer->read($file);
                $summary = isset($report['summary']) && is_array($report['summary'])
                    ? $report['summary']
                    : $this->buildLegacySummary($report);
                $summary['report_path'] = $file;
                $summary['report_size'] = filesize($file) ?: 0;
                $summary['modified_at'] = date('c', filemtime($file) ?: time());
                $reports[] = $summary;
            } catch (RuntimeException $exception) {
                continue;
            }
        }

        return $reports;
    }

    public function reportExists(string $scanId): bool
    {
        return is_file($this->getReportPath($scanId));
    }

    public function deleteReport(string $scanId): bool
    {
        $path = $this->getReportPath($scanId);

        if (!is_file($path)) {
            return false;
        }

        if (!unlink($path)) {
            throw new RuntimeException('Cannot delete report');
        }

        return true;
    }

    private function buildReport(array $session): array
    {
        $results = isset($session['results']) && is_array($session['results']) ? $session['results'] : [];
        $summary = [
            'scan_id' => (string)$session['scan_id'],
            'status' => (string)$session['status'],
            'started_at' => isset($session['started_at']) ? (string)$session['started_at'] : '',
            'finished_at' => isset($session['finished_at']) ? (string)$session['finished_at'] : '',
            'path' => isset($session['config']['path']) ? (string)$session['config']['path'] : '',
            'profile' => isset($session['config']['profile']) ? (string)$session['config']['profile'] : '',
            'action' => isset($session['config']['action']) ? (string)$session['config']['action'] : '',
            'dry_run' => isset($session['config']['dry_run']) ? (bool)$session['config']['dry_run'] : true,
            'processed_files' => isset($session['processed_files']) ? (int)$session['processed_files'] : 0,
            'total_files_estimated' => isset($session['total_files_estimated']) ? (int)$session['total_files_estimated'] : 0,
            'found_total' => isset($session['found_total']) ? (int)$session['found_total'] : 0,
            'runtime_errors' => isset($session['runtime_errors']) ? (int)$session['runtime_errors'] : 0,
            'findings_total' => $this->countFindings($results),
        ];

        return [
            'format' => 'delement.antivirus.report',
            'format_version' => 1,
            'created_at' => date('c'),
            'summary' => $summary,
            'config' => isset($session['config']) && is_array($session['config']) ? $session['config'] : [],
            'results' => $results,
        ];
    }

    private function buildLegacySummary(array $report): array
    {
        $results = isset($report['results']) && is_array($report['results']) ? $report['results'] : [];

        return [
            'scan_id' => isset($report['scan_id']) ? (string)$report['scan_id'] : '',
            'status' => isset($report['status']) ? (string)$report['status'] : '',
            'started_at' => isset($report['started_at']) ? (string)$report['started_at'] : '',
            'finished_at' => isset($report['finished_at']) ? (string)$report['finished_at'] : '',
            'path' => isset($report['path']) ? (string)$report['path'] : '',
            'profile' => '',
            'action' => '',
            'dry_run' => true,
            'processed_files' => isset($report['processed_files']) ? (int)$report['processed_files'] : 0,
            'total_files_estimated' => isset($report['total_files_estimated']) ? (int)$report['total_files_estimated'] : 0,
            'found_total' => isset($report['found_total']) ? (int)$report['found_total'] : 0,
            'runtime_errors' => isset($report['runtime_errors']) ? (int)$report['runtime_errors'] : 0,
            'findings_total' => $this->countFindings($results),
        ];
    }

    private function countFindings(array $results): int
    {
        $total = 0;

        foreach ($results as $result) {
            if (isset($result['findings']) && is_array($result['findings'])) {
                $total += count($result['findings']);
            }
        }

        return $total;
    }

    private function getReportPath(string $scanId): string
    {
        return $this->reportsPath . '/' . $this->sanitizeScanId($scanId) . '.json';
    }

    private function sanitizeScanId(string $scanId): string
    {
        if (!preg_match('/^[a-zA-Z0-9_.-]+$/', $scanId)) {
            throw new RuntimeException('Invalid scan id');
        }

        return $scanId;
    }

}
