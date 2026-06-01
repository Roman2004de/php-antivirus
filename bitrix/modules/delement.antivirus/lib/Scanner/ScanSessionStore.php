<?php

namespace Delement\Antivirus\Scanner;

use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\Storage\RuntimeDirectory;
use RuntimeException;

class ScanSessionStore
{
    private $sessionsPath;

    public function __construct(string $moduleRoot = null)
    {
        $moduleRoot = $moduleRoot ?: dirname(__DIR__, 2);
        $this->sessionsPath = RuntimeDirectory::resolve($moduleRoot, 'sessions');
    }

    public function create(ScanConfig $config, array $files, int $createdBy = 0): array
    {
        $scanId = $this->createScanId();
        $session = [
            'scan_id' => $scanId,
            'status' => 'created',
            'started_at' => date('c'),
            'finished_at' => null,
            'created_by' => $createdBy,
            'config' => $config->toArray(),
            'files' => array_values($files),
            'cursor' => 0,
            'processed_files' => 0,
            'total_files_estimated' => count($files),
            'found_total' => 0,
            'runtime_errors' => 0,
            'current_file' => '',
            'results' => [],
            'report_path' => '',
        ];

        $this->save($session);

        return $session;
    }

    public function load(string $scanId): array
    {
        $path = $this->getSessionPath($scanId);

        if (!is_file($path) || !is_readable($path)) {
            throw new RuntimeException('Scan session not found');
        }

        $data = json_decode((string)file_get_contents($path), true);

        if (!is_array($data)) {
            throw new RuntimeException('Scan session is corrupted');
        }

        return $data;
    }

    public function save(array $session): void
    {
        $this->ensureDirectory($this->sessionsPath);

        if (empty($session['scan_id'])) {
            throw new RuntimeException('Scan session id is empty');
        }

        $json = json_encode($session, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        if ($json === false) {
            throw new RuntimeException('Cannot encode scan session');
        }

        $path = $this->getSessionPath((string)$session['scan_id']);

        if (file_put_contents($path, $json, LOCK_EX) === false) {
            throw new RuntimeException('Cannot save scan session to ' . $path);
        }
    }

    private function createScanId(): string
    {
        return date('Ymd_His') . '_' . bin2hex(random_bytes(6));
    }

    private function getSessionPath(string $scanId): string
    {
        return $this->sessionsPath . '/' . $this->sanitizeScanId($scanId) . '.json';
    }

    private function sanitizeScanId(string $scanId): string
    {
        if (!preg_match('/^[a-zA-Z0-9_.-]+$/', $scanId)) {
            throw new RuntimeException('Invalid scan id');
        }

        return $scanId;
    }

    private function ensureDirectory(string $path): void
    {
        if (!is_dir($path) && !@mkdir($path, 0755, true) && !is_dir($path)) {
            throw new RuntimeException('Cannot create scan session directory: ' . $path);
        }

        if (!is_writable($path)) {
            throw new RuntimeException('Scan session directory is not writable: ' . $path);
        }
    }
}
