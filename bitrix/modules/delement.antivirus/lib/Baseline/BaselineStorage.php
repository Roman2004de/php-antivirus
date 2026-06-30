<?php

namespace Delement\Antivirus\Baseline;

use Delement\Antivirus\Storage\RuntimeDirectory;
use RuntimeException;

class BaselineStorage
{
    private const FILE_MODE = 0600;
    private const DIRECTORY_MODE = 0700;

    private $baselinePath;

    public function __construct(string $moduleRoot = null)
    {
        $moduleRoot = $moduleRoot ?: dirname(__DIR__, 2);
        $this->baselinePath = RuntimeDirectory::resolve($moduleRoot, 'baseline');
        $this->ensureDirectory($this->reportsDirectory());
    }

    public function exists(): bool
    {
        return is_file($this->snapshotPath());
    }

    public function saveSnapshot(array $snapshot): string
    {
        $path = $this->snapshotPath();
        $this->writeJson($path, $snapshot);

        return $path;
    }

    public function loadSnapshot(): array
    {
        return $this->readJson($this->snapshotPath());
    }

    public function saveReport(array $report): string
    {
        $reportId = isset($report['report_id']) ? (string)$report['report_id'] : $this->createReportId();
        $report['report_id'] = $reportId;
        $path = $this->reportsDirectory() . DIRECTORY_SEPARATOR . $this->sanitizeId($reportId) . '.json';
        $this->writeJson($path, $report);
        $this->writeJson($this->latestReportPath(), [
            'report_id' => $reportId,
            'path' => $path,
            'created_at' => date('c'),
        ]);

        return $path;
    }

    public function loadLatestReport(): array
    {
        $metaPath = $this->latestReportPath();

        if (!is_file($metaPath)) {
            return [];
        }

        $meta = $this->readJson($metaPath);
        $path = isset($meta['path']) ? (string)$meta['path'] : '';

        if ($path === '' || !is_file($path)) {
            return [];
        }

        return $this->readJson($path);
    }

    public function latestReportPathFromMeta(): string
    {
        $metaPath = $this->latestReportPath();

        if (!is_file($metaPath)) {
            return '';
        }

        try {
            $meta = $this->readJson($metaPath);
        } catch (RuntimeException $exception) {
            return '';
        }

        $path = isset($meta['path']) ? (string)$meta['path'] : '';

        return $path !== '' && is_file($path) ? $path : '';
    }

    public function listReports(int $limit = 20): array
    {
        $files = glob($this->reportsDirectory() . DIRECTORY_SEPARATOR . '*.json');

        if (!is_array($files)) {
            return [];
        }

        usort($files, static function ($left, $right) {
            return filemtime($right) <=> filemtime($left);
        });

        $reports = [];

        foreach (array_slice($files, 0, max(1, $limit)) as $file) {
            try {
                $report = $this->readJson($file);
                $report['report_path'] = $file;
                $reports[] = $report;
            } catch (RuntimeException $exception) {
                continue;
            }
        }

        return $reports;
    }

    private function snapshotPath(): string
    {
        return $this->baselinePath . DIRECTORY_SEPARATOR . 'baseline.json';
    }

    private function latestReportPath(): string
    {
        return $this->baselinePath . DIRECTORY_SEPARATOR . 'latest_report.json';
    }

    private function reportsDirectory(): string
    {
        return $this->baselinePath . DIRECTORY_SEPARATOR . 'reports';
    }

    private function createReportId(): string
    {
        return gmdate('Ymd_His') . '_' . bin2hex(random_bytes(6));
    }

    private function sanitizeId(string $id): string
    {
        if (!preg_match('/^[a-zA-Z0-9_.-]+$/', $id)) {
            throw new RuntimeException('baseline_report_id_invalid');
        }

        return $id;
    }

    private function readJson(string $path): array
    {
        if (!is_file($path) || !is_readable($path)) {
            throw new RuntimeException('baseline_storage_file_not_readable');
        }

        $json = file_get_contents($path);

        if ($json === false || trim($json) === '') {
            throw new RuntimeException('baseline_storage_file_empty');
        }

        $data = json_decode($json, true);

        if (!is_array($data)) {
            throw new RuntimeException('baseline_storage_json_invalid');
        }

        return $data;
    }

    private function writeJson(string $path, array $data): void
    {
        $this->ensureDirectory(dirname($path));
        $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        if ($json === false) {
            throw new RuntimeException('baseline_storage_json_encode_failed');
        }

        if (file_put_contents($path, $json . PHP_EOL, LOCK_EX) === false) {
            throw new RuntimeException('baseline_storage_write_failed');
        }

        @chmod($path, self::FILE_MODE);
    }

    private function ensureDirectory(string $path): void
    {
        if (is_dir($path)) {
            @chmod($path, self::DIRECTORY_MODE);
            return;
        }

        if (!mkdir($path, self::DIRECTORY_MODE, true) && !is_dir($path)) {
            throw new RuntimeException('baseline_storage_directory_create_failed');
        }

        @chmod($path, self::DIRECTORY_MODE);
    }
}
