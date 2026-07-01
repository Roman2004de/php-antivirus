<?php

namespace Delement\Antivirus\Scanner;

use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\Storage\RuntimeDirectory;
use RuntimeException;

class ScanSessionStore
{
    private const ACTIVE_STATUSES = ['created', 'running', 'progress'];
    private const DIRECTORY_MODE = 0700;
    private const FILE_MODE = 0600;

    private $sessionsPath;

    public function __construct(string $moduleRoot = null)
    {
        $moduleRoot = $moduleRoot ?: dirname(__DIR__, 2);
        $this->sessionsPath = RuntimeDirectory::resolve($moduleRoot, 'sessions');
    }

    public function create(ScanConfig $config, array $files, int $createdBy = 0): array
    {
        $session = $this->buildSession($config, $files, $createdBy);

        $this->save($session);

        return $session;
    }

    public function createActive(ScanConfig $config, int $createdBy = 0): array
    {
        if (!$this->hasSessionStorage()) {
            return $this->create($config, [], $createdBy);
        }

        return $this->withActiveLock(function () use ($config, $createdBy) {
            $activeSession = $this->readActiveSessionUnsafe();

            if ($activeSession !== null) {
                return [
                    'active_conflict' => true,
                    'active_session' => $activeSession,
                ];
            }

            $session = $this->buildSession($config, [], $createdBy);
            $this->save($session);
            $this->writeActiveMarkerUnsafe($session);

            return $session;
        });
    }

    public function load(string $scanId): array
    {
        $path = $this->getSessionPath($scanId);

        if (!is_file($path) || !is_readable($path)) {
            throw new RuntimeException('scan_session_not_found');
        }

        $data = json_decode((string)file_get_contents($path), true);

        if (!is_array($data)) {
            throw new RuntimeException('scan_session_corrupted');
        }

        return $data;
    }

    public function save(array $session): void
    {
        $this->ensureDirectory($this->sessionsPath);

        if (empty($session['scan_id'])) {
            throw new RuntimeException('scan_session_id_empty');
        }

        $json = json_encode($session, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        if ($json === false) {
            throw new RuntimeException('scan_session_encode_failed');
        }

        $path = $this->getSessionPath((string)$session['scan_id']);

        if (file_put_contents($path, $json, LOCK_EX) === false) {
            throw new RuntimeException('scan_session_save_failed');
        }

        @chmod($path, self::FILE_MODE);
    }

    public function saveActive(array $session): void
    {
        $this->save($session);

        if (!$this->hasSessionStorage()) {
            return;
        }

        $this->syncActiveMarker($session);
    }

    public function getActiveSession(): ?array
    {
        if (!$this->hasSessionStorage()) {
            return null;
        }

        return $this->withActiveLock(function () {
            return $this->readActiveSessionUnsafe();
        });
    }

    public function releaseActive(string $scanId): void
    {
        if (!$this->hasSessionStorage()) {
            return;
        }

        $this->withActiveLock(function () use ($scanId) {
            $marker = $this->readActiveMarkerUnsafe();

            if ((string)($marker['scan_id'] ?? '') === $scanId) {
                @unlink($this->getActiveMarkerPath());
            }
        });
    }

    private function buildSession(ScanConfig $config, array $files, int $createdBy): array
    {
        return [
            'scan_id' => $this->createScanId(),
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
            'informational_findings_total' => 0,
            'runtime_errors' => 0,
            'current_file' => '',
            'results' => [],
            'bitrix_db_scanned' => false,
            'bitrix_db_results_total' => 0,
            'report_path' => '',
        ];
    }

    private function syncActiveMarker(array $session): void
    {
        $this->withActiveLock(function () use ($session) {
            $scanId = isset($session['scan_id']) ? (string)$session['scan_id'] : '';
            $marker = $this->readActiveMarkerUnsafe();
            $markerScanId = (string)($marker['scan_id'] ?? '');

            if ($scanId === '') {
                return;
            }

            if ($this->isActiveStatus((string)($session['status'] ?? ''))) {
                if ($markerScanId === '' || $markerScanId === $scanId) {
                    $this->writeActiveMarkerUnsafe($session);
                }

                return;
            }

            if ($markerScanId === $scanId) {
                @unlink($this->getActiveMarkerPath());
            }
        });
    }

    private function readActiveSessionUnsafe(): ?array
    {
        $marker = $this->readActiveMarkerUnsafe();
        $scanId = (string)($marker['scan_id'] ?? '');

        if ($scanId === '') {
            return null;
        }

        try {
            $session = $this->load($scanId);
        } catch (RuntimeException $exception) {
            @unlink($this->getActiveMarkerPath());
            return null;
        }

        if (!$this->isActiveStatus((string)($session['status'] ?? ''))) {
            @unlink($this->getActiveMarkerPath());
            return null;
        }

        $this->writeActiveMarkerUnsafe($session);

        return $this->activePayload($session);
    }

    private function readActiveMarkerUnsafe(): array
    {
        $path = $this->getActiveMarkerPath();

        if (!is_file($path) || !is_readable($path)) {
            return [];
        }

        $data = json_decode((string)file_get_contents($path), true);

        return is_array($data) ? $data : [];
    }

    private function writeActiveMarkerUnsafe(array $session): void
    {
        $payload = $this->activePayload($session);
        $payload['updated_at'] = date('c');
        $json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        if ($json === false) {
            throw new RuntimeException('active_scan_marker_encode_failed');
        }

        if (file_put_contents($this->getActiveMarkerPath(), $json, LOCK_EX) === false) {
            throw new RuntimeException('active_scan_marker_save_failed');
        }

        @chmod($this->getActiveMarkerPath(), self::FILE_MODE);
    }

    private function activePayload(array $session): array
    {
        return [
            'scan_id' => isset($session['scan_id']) ? (string)$session['scan_id'] : '',
            'status' => isset($session['status']) ? (string)$session['status'] : '',
            'started_at' => isset($session['started_at']) ? (string)$session['started_at'] : '',
            'created_by' => isset($session['created_by']) ? (int)$session['created_by'] : 0,
            'processed_files' => isset($session['processed_files']) ? (int)$session['processed_files'] : 0,
            'total_files_estimated' => isset($session['total_files_estimated']) ? (int)$session['total_files_estimated'] : 0,
            'files_discovered' => isset($session['files_discovered']) ? (int)$session['files_discovered'] : 0,
            'found_total' => isset($session['found_total']) ? (int)$session['found_total'] : 0,
            'informational_findings_total' => isset($session['informational_findings_total']) ? (int)$session['informational_findings_total'] : 0,
            'runtime_errors' => isset($session['runtime_errors']) ? (int)$session['runtime_errors'] : 0,
            'bitrix_db_results_total' => isset($session['bitrix_db_results_total']) ? (int)$session['bitrix_db_results_total'] : 0,
            'current_file' => isset($session['current_file']) ? (string)$session['current_file'] : '',
            'discovery_done' => !empty($session['discovery_done']),
        ];
    }

    private function withActiveLock(callable $callback)
    {
        if (!$this->hasSessionStorage()) {
            return $callback();
        }

        $this->ensureDirectory($this->sessionsPath);
        $lockPath = $this->getActiveLockPath();
        $handle = @fopen($lockPath, 'c+');

        if ($handle === false) {
            throw new RuntimeException('active_scan_lock_open_failed');
        }

        @chmod($lockPath, self::FILE_MODE);

        if (!flock($handle, LOCK_EX)) {
            fclose($handle);
            throw new RuntimeException('active_scan_lock_acquire_failed');
        }

        try {
            return $callback();
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    private function isActiveStatus(string $status): bool
    {
        return in_array($status, self::ACTIVE_STATUSES, true);
    }

    private function hasSessionStorage(): bool
    {
        return is_string($this->sessionsPath) && $this->sessionsPath !== '';
    }

    private function createScanId(): string
    {
        return date('Ymd_His') . '_' . bin2hex(random_bytes(6));
    }

    private function getSessionPath(string $scanId): string
    {
        return $this->sessionsPath . '/' . $this->sanitizeScanId($scanId) . '.json';
    }

    private function getActiveMarkerPath(): string
    {
        return $this->sessionsPath . '/active.json';
    }

    private function getActiveLockPath(): string
    {
        return $this->sessionsPath . '/active.lock';
    }

    private function sanitizeScanId(string $scanId): string
    {
        if (!preg_match('/^[a-zA-Z0-9_.-]+$/', $scanId)) {
            throw new RuntimeException('scan_id_invalid');
        }

        return $scanId;
    }

    private function ensureDirectory(string $path): void
    {
        if (!is_dir($path) && !@mkdir($path, self::DIRECTORY_MODE, true) && !is_dir($path)) {
            throw new RuntimeException('scan_session_directory_create_failed');
        }

        if (!is_writable($path)) {
            throw new RuntimeException('scan_session_directory_not_writable');
        }

        @chmod($path, self::DIRECTORY_MODE);
    }
}
