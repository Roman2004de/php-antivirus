<?php

namespace Delement\Antivirus\Report;

use Delement\Antivirus\Detection\Tags\ResultTagger;
use Delement\Antivirus\Storage\RuntimeDirectory;
use RuntimeException;

class ReportManager
{
    private $reportsPath;
    private $writer;
    private $resultTagger;

    public function __construct(string $moduleRoot = null, JsonReportWriter $writer = null, ResultTagger $resultTagger = null)
    {
        $moduleRoot = $moduleRoot ?: dirname(__DIR__, 2);
        $this->reportsPath = RuntimeDirectory::resolve($moduleRoot, 'reports');
        $this->writer = $writer ?: new JsonReportWriter();
        $this->resultTagger = $resultTagger;

        if ($this->resultTagger === null && class_exists(ResultTagger::class)) {
            $this->resultTagger = new ResultTagger();
        }
    }

    public function saveFromSession(array $session): string
    {
        if (empty($session['scan_id'])) {
            throw new RuntimeException('scan_session_id_empty');
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
                $results = isset($report['results']) && is_array($report['results']) ? $report['results'] : [];
                $summaryTags = isset($summary['tags']) && is_array($summary['tags']) ? self::normalizeTags($summary['tags']) : [];
                $summary['tags'] = !empty($summaryTags) ? $summaryTags : $this->collectTags($results);
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
            throw new RuntimeException('scan_report_delete_failed');
        }

        return true;
    }

    private function buildReport(array $session): array
    {
        $results = isset($session['results']) && is_array($session['results']) ? $session['results'] : [];
        $results = $this->tagResults($results);
        $path = isset($session['config']['path']) ? (string)$session['config']['path'] : '';
        $scanPaths = isset($session['config']['scan_paths']) && is_array($session['config']['scan_paths']) ? $session['config']['scan_paths'] : [];

        if (empty($scanPaths) && $path !== '') {
            $scanPaths = [$path];
        }

        $summary = [
            'scan_id' => (string)$session['scan_id'],
            'status' => (string)$session['status'],
            'started_at' => isset($session['started_at']) ? (string)$session['started_at'] : '',
            'finished_at' => isset($session['finished_at']) ? (string)$session['finished_at'] : '',
            'path' => $path,
            'scan_profile' => isset($session['config']['scan_profile']) ? (string)$session['config']['scan_profile'] : 'standard',
            'scan_paths' => $scanPaths,
            'profile' => isset($session['config']['profile']) ? (string)$session['config']['profile'] : '',
            'action' => isset($session['config']['action']) ? (string)$session['config']['action'] : '',
            'dry_run' => isset($session['config']['dry_run']) ? (bool)$session['config']['dry_run'] : true,
            'processed_files' => isset($session['processed_files']) ? (int)$session['processed_files'] : 0,
            'total_files_estimated' => isset($session['total_files_estimated']) ? (int)$session['total_files_estimated'] : 0,
            'found_total' => isset($session['found_total']) ? (int)$session['found_total'] : 0,
            'runtime_errors' => isset($session['runtime_errors']) ? (int)$session['runtime_errors'] : 0,
            'findings_total' => $this->countFindings($results),
            'informational_findings_total' => isset($session['informational_findings_total'])
                ? (int)$session['informational_findings_total']
                : $this->countInformationalFindings($results),
            'tags' => $this->collectTags($results),
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
            'scan_profile' => 'standard',
            'scan_paths' => isset($report['path']) && (string)$report['path'] !== '' ? [(string)$report['path']] : [],
            'profile' => '',
            'action' => '',
            'dry_run' => true,
            'processed_files' => isset($report['processed_files']) ? (int)$report['processed_files'] : 0,
            'total_files_estimated' => isset($report['total_files_estimated']) ? (int)$report['total_files_estimated'] : 0,
            'found_total' => isset($report['found_total']) ? (int)$report['found_total'] : 0,
            'runtime_errors' => isset($report['runtime_errors']) ? (int)$report['runtime_errors'] : 0,
            'findings_total' => $this->countFindings($results),
            'informational_findings_total' => $this->countInformationalFindings($results),
            'tags' => $this->collectTags($results),
        ];
    }

    private function tagResults(array $results): array
    {
        if ($this->resultTagger === null) {
            return $results;
        }

        $tagged = [];

        foreach ($results as $result) {
            $tagged[] = is_array($result) ? $this->resultTagger->tagResultArray($result) : $result;
        }

        return $tagged;
    }

    private function collectTags(array $results): array
    {
        $tags = [];

        foreach ($results as $result) {
            if (!is_array($result)) {
                continue;
            }

            if ($this->resultTagger !== null) {
                $tags = self::mergeTags($tags, $this->resultTagger->tagsForResultArray($result));
                continue;
            }

            if (isset($result['tags']) && is_array($result['tags'])) {
                $tags = self::mergeTags($tags, $result['tags']);
            }
        }

        return self::normalizeTags($tags);
    }

    private static function mergeTags(array ...$tagSets): array
    {
        $tags = [];

        foreach ($tagSets as $tagSet) {
            foreach ($tagSet as $tag) {
                $tags[] = $tag;
            }
        }

        return self::normalizeTags($tags);
    }

    private static function normalizeTags(array $tags): array
    {
        $result = [];
        $seen = [];

        foreach ($tags as $tag) {
            $tag = strtolower(trim((string)$tag));

            if ($tag === '' || isset($seen[$tag])) {
                continue;
            }

            $result[] = $tag;
            $seen[$tag] = true;
        }

        sort($result, SORT_STRING);

        return $result;
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

    private function countInformationalFindings(array $results): int
    {
        $total = 0;

        foreach ($results as $result) {
            if (!isset($result['findings']) || !is_array($result['findings'])) {
                continue;
            }

            foreach ($result['findings'] as $finding) {
                if (is_array($finding) && (int)($finding['score'] ?? 0) <= 0) {
                    $total++;
                }
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
            throw new RuntimeException('scan_id_invalid');
        }

        return $scanId;
    }

}
