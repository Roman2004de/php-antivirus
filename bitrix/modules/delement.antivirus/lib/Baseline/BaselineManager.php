<?php

namespace Delement\Antivirus\Baseline;

use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\Detection\Baseline\BaselineAnalyzer;
use Delement\Antivirus\Detection\Severity;
use Delement\Antivirus\File\FileFilter;
use Delement\Antivirus\File\FileTypeDetector;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use FilesystemIterator;
use RuntimeException;

class BaselineManager
{
    private $storage;
    private $analyzer;
    private $fileFilter;
    private $fileTypeDetector;

    public function __construct(
        BaselineStorage $storage = null,
        BaselineAnalyzer $analyzer = null,
        FileFilter $fileFilter = null,
        FileTypeDetector $fileTypeDetector = null
    ) {
        $this->storage = $storage ?: new BaselineStorage();
        $this->analyzer = $analyzer ?: new BaselineAnalyzer();
        $this->fileFilter = $fileFilter ?: new FileFilter();
        $this->fileTypeDetector = $fileTypeDetector ?: new FileTypeDetector();
    }

    public function createBaseline(ScanConfig $config): array
    {
        $snapshot = $this->buildSnapshot($config);
        $snapshotPath = $this->storage->saveSnapshot($snapshot);
        $report = $this->buildOperationReport('create', $snapshot, [], $snapshotPath);
        $reportPath = $this->storage->saveReport($report);
        $report['report_path'] = $reportPath;

        return $report;
    }

    public function checkBaseline(ScanConfig $config): array
    {
        if (!$this->storage->exists()) {
            throw new RuntimeException('baseline_snapshot_not_found');
        }

        $snapshot = $this->storage->loadSnapshot();
        $currentSnapshot = $this->buildSnapshot($config);
        $baselineRecords = isset($snapshot['records']) && is_array($snapshot['records']) ? $snapshot['records'] : [];
        $currentRecords = isset($currentSnapshot['records']) && is_array($currentSnapshot['records']) ? $currentSnapshot['records'] : [];
        $results = $this->analyzer->analyze($baselineRecords, $currentRecords, $config);
        $report = $this->buildOperationReport('check', $snapshot, $results, '', $currentSnapshot);
        $reportPath = $this->storage->saveReport($report);
        $report['report_path'] = $reportPath;

        return $report;
    }

    public function updateBaseline(ScanConfig $config): array
    {
        $snapshot = $this->buildSnapshot($config);
        $snapshotPath = $this->storage->saveSnapshot($snapshot);
        $report = $this->buildOperationReport('update', $snapshot, [], $snapshotPath);
        $reportPath = $this->storage->saveReport($report);
        $report['report_path'] = $reportPath;

        return $report;
    }

    public function latestReport(): array
    {
        return $this->storage->loadLatestReport();
    }

    public function latestReportPath(): string
    {
        return $this->storage->latestReportPathFromMeta();
    }

    public function hasBaseline(): bool
    {
        return $this->storage->exists();
    }

    private function buildSnapshot(ScanConfig $config): array
    {
        $records = $this->collectRecords($config);

        return [
            'format' => 'delement.antivirus.baseline',
            'format_version' => 1,
            'created_at' => date('c'),
            'document_root' => $config->getDocumentRoot(),
            'path' => $config->getPath(),
            'scan_paths' => $config->getScanPaths(),
            'normalized_hash_enabled' => $config->isNormalizedHashEnabled(),
            'normalized_hash_max_file_size_bytes' => $config->getNormalizedHashMaxFileSizeBytes(),
            'records_count' => count($records),
            'records' => array_map(static function (BaselineRecord $record) {
                return $record->toArray();
            }, $records),
        ];
    }

    private function collectRecords(ScanConfig $config): array
    {
        $records = [];
        $seen = [];
        $createdAt = date('c');

        foreach ($config->getScanPaths() as $path) {
            foreach ($this->collectFiles((string)$path, $config) as $filePath) {
                $relativePath = $this->relativePath((string)$filePath, $config);
                $key = strtolower(str_replace('\\', '/', $relativePath !== '' ? $relativePath : (string)$filePath));

                if (isset($seen[$key])) {
                    continue;
                }

                $record = $this->recordForFile((string)$filePath, $relativePath, $createdAt, $config);

                if ($record === null) {
                    continue;
                }

                $records[] = $record;
                $seen[$key] = true;
            }
        }

        usort($records, static function (BaselineRecord $left, BaselineRecord $right) {
            return strcmp($left->getRelativePath(), $right->getRelativePath());
        });

        return $records;
    }

    private function collectFiles(string $path, ScanConfig $config): iterable
    {
        if (!file_exists($path)) {
            if ($config->ignoresMissingScanPaths()) {
                return;
            }

            throw new RuntimeException('baseline_path_not_found');
        }

        if (is_file($path)) {
            if ($this->isTrackableFile($path, $config)) {
                yield $path;
            }

            return;
        }

        if (!is_dir($path)) {
            throw new RuntimeException('baseline_path_not_regular_file_or_directory');
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $fileInfo) {
            $filePath = $fileInfo->getPathname();

            if ($fileInfo->isDir() || $fileInfo->isLink()) {
                continue;
            }

            if ($this->isTrackableFile($filePath, $config)) {
                yield $filePath;
            }
        }
    }

    private function isTrackableFile(string $filePath, ScanConfig $config): bool
    {
        if (!is_file($filePath) || !is_readable($filePath)) {
            return false;
        }

        if ($this->fileFilter->isExcluded($filePath, $config)) {
            return false;
        }

        $size = @filesize($filePath);

        if ($size === false || $size > $config->getMaxFileSizeBytes()) {
            return false;
        }

        return true;
    }

    private function recordForFile(string $filePath, string $relativePath, string $createdAt, ScanConfig $config): ?BaselineRecord
    {
        $size = @filesize($filePath);
        $mtime = @filemtime($filePath);
        $sha256 = @hash_file('sha256', $filePath);

        if ($size === false || $mtime === false || $sha256 === false) {
            return null;
        }

        return new BaselineRecord([
            'path' => $filePath,
            'relative_path' => $relativePath,
            'size' => $size,
            'mtime' => $mtime,
            'sha256' => strtolower($sha256),
            'normalized_hash' => $this->normalizedHash($filePath, $config),
            'created_at' => $createdAt,
        ]);
    }

    private function normalizedHash(string $filePath, ScanConfig $config): ?string
    {
        if (!$config->isNormalizedHashEnabled()) {
            return null;
        }

        $size = @filesize($filePath);

        if ($size === false || $size > $config->getNormalizedHashMaxFileSizeBytes()) {
            return null;
        }

        if ($this->fileTypeDetector->isBinary($filePath)) {
            return null;
        }

        $content = @file_get_contents($filePath);

        if ($content === false || strpos($content, "\0") !== false) {
            return null;
        }

        $normalized = preg_replace('/\s+/', '', $content);

        return $normalized === null ? null : hash('sha256', $normalized);
    }

    private function relativePath(string $filePath, ScanConfig $config): string
    {
        $documentRoot = rtrim(str_replace('\\', '/', $config->getDocumentRoot()), '/');
        $normalizedPath = str_replace('\\', '/', $filePath);

        if ($documentRoot !== '' && ($normalizedPath === $documentRoot || strpos($normalizedPath, $documentRoot . '/') === 0)) {
            return '/' . ltrim(substr($normalizedPath, strlen($documentRoot)), '/');
        }

        $scanPath = rtrim(str_replace('\\', '/', $config->getPath()), '/');

        if ($scanPath !== '' && ($normalizedPath === $scanPath || strpos($normalizedPath, $scanPath . '/') === 0)) {
            return '/' . ltrim(substr($normalizedPath, strlen($scanPath)), '/');
        }

        return $normalizedPath;
    }

    private function buildOperationReport(
        string $operation,
        array $snapshot,
        array $results,
        string $snapshotPath = '',
        array $currentSnapshot = []
    ): array {
        $summary = $this->buildSummary($operation, $snapshot, $results, $snapshotPath, $currentSnapshot);

        return [
            'format' => 'delement.antivirus.baseline_report',
            'format_version' => 1,
            'report_id' => gmdate('Ymd_His') . '_' . substr(hash('sha256', $operation . microtime(true) . random_int(1, PHP_INT_MAX)), 0, 12),
            'created_at' => date('c'),
            'summary' => $summary,
            'results' => $results,
        ];
    }

    private function buildSummary(
        string $operation,
        array $snapshot,
        array $results,
        string $snapshotPath,
        array $currentSnapshot
    ): array {
        $counts = $this->countResults($results);
        $tags = $this->collectTags($results);

        return [
            'operation' => $operation,
            'status' => empty($results) ? ($operation === 'check' ? 'clean' : 'finished') : 'changed',
            'path' => isset($snapshot['path']) ? (string)$snapshot['path'] : '',
            'document_root' => isset($snapshot['document_root']) ? (string)$snapshot['document_root'] : '',
            'baseline_created_at' => isset($snapshot['created_at']) ? (string)$snapshot['created_at'] : '',
            'current_created_at' => isset($currentSnapshot['created_at']) ? (string)$currentSnapshot['created_at'] : '',
            'snapshot_path' => $snapshotPath,
            'baseline_records' => isset($snapshot['records_count']) ? (int)$snapshot['records_count'] : count((array)($snapshot['records'] ?? [])),
            'current_files' => isset($currentSnapshot['records_count']) ? (int)$currentSnapshot['records_count'] : 0,
            'findings_total' => $counts['findings_total'],
            'changed_files' => count($results),
            'new_files' => $counts['new_files'],
            'modified_files' => $counts['modified_files'],
            'deleted_files' => $counts['deleted_files'],
            'critical_changes' => $counts['critical_changes'],
            'tags' => $tags,
        ];
    }

    private function countResults(array $results): array
    {
        $counts = [
            'findings_total' => 0,
            'new_files' => 0,
            'modified_files' => 0,
            'deleted_files' => 0,
            'critical_changes' => 0,
        ];

        foreach ($results as $result) {
            $hasNew = false;
            $hasModified = false;
            $hasDeleted = false;
            $hasCritical = in_array((string)($result['severity'] ?? ''), [Severity::HIGH, Severity::CRITICAL], true);

            foreach ((array)($result['findings'] ?? []) as $finding) {
                if (!is_array($finding)) {
                    continue;
                }

                $counts['findings_total']++;
                $signatureId = (string)($finding['signature_id'] ?? '');

                if ($signatureId === 'baseline_new_file') {
                    $hasNew = true;
                } elseif ($signatureId === 'baseline_modified_file') {
                    $hasModified = true;
                } elseif ($signatureId === 'baseline_deleted_file') {
                    $hasDeleted = true;
                }

                if (in_array($signatureId, ['baseline_critical_path_modified', 'baseline_php_in_upload', 'baseline_unknown_file_in_tools'], true)) {
                    $hasCritical = true;
                }
            }

            $counts['new_files'] += $hasNew ? 1 : 0;
            $counts['modified_files'] += $hasModified ? 1 : 0;
            $counts['deleted_files'] += $hasDeleted ? 1 : 0;
            $counts['critical_changes'] += $hasCritical ? 1 : 0;
        }

        return $counts;
    }

    private function collectTags(array $results): array
    {
        $tags = [];
        $seen = [];

        foreach ($results as $result) {
            foreach ((array)($result['tags'] ?? []) as $tag) {
                $tag = strtolower(trim((string)$tag));

                if ($tag !== '' && !isset($seen[$tag])) {
                    $tags[] = $tag;
                    $seen[$tag] = true;
                }
            }
        }

        sort($tags, SORT_STRING);

        return $tags;
    }
}
