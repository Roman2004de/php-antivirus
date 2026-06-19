<?php

namespace Delement\Antivirus\Scanner;

use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\File\FileCollector;
use Delement\Antivirus\Report\ReportManager;
use Delement\Antivirus\Whitelist\WhitelistManager;
use RuntimeException;
use Throwable;

class ScanRunService
{
    private $documentRoot;
    private $moduleRoot;
    private $store;
    private $reportManager;
    private $collector;
    private $scanner;
    private $actionApplier;
    private $whitelistManager;

    public function __construct(
        string $documentRoot,
        ScanSessionStore $store = null,
        ReportManager $reportManager = null,
        string $moduleRoot = null,
        FileCollector $collector = null,
        Scanner $scanner = null,
        ScanActionApplier $actionApplier = null,
        WhitelistManager $whitelistManager = null
    ) {
        $this->documentRoot = rtrim($documentRoot, '/\\');
        $this->moduleRoot = $moduleRoot ?: dirname(__DIR__, 2);
        $this->store = $store ?: new ScanSessionStore($this->moduleRoot);
        $this->reportManager = $reportManager ?: new ReportManager($this->moduleRoot);
        $this->collector = $collector ?: new FileCollector();
        $this->scanner = $scanner ?: new Scanner();
        $this->actionApplier = $actionApplier ?: new ScanActionApplier($this->documentRoot);
        $this->whitelistManager = $whitelistManager;
    }

    public function start(ScanConfig $config, int $createdBy = 0): array
    {
        $scanPaths = $this->validateScanPaths($config);
        $session = $this->store->createActive($config, $createdBy);

        if (!empty($session['active_conflict']) && isset($session['active_session']) && is_array($session['active_session'])) {
            return $this->activeScanConflictPayload($session['active_session']);
        }

        try {
            if (isset($session['config']) && is_array($session['config'])) {
                $session['config']['scan_profile'] = $config->getScanProfile();
                $session['config']['scan_paths'] = $scanPaths;
            }

            $session['files'] = [];
            $session['discovery_state'] = $this->collector->createDiscoveryState($scanPaths);
            $session['discovery_done'] = empty($session['discovery_state']['pending']);
            $session['files_discovered'] = 0;
            $session['total_files_estimated'] = 0;
            $session['status'] = 'running';
            $this->store->saveActive($session);
        } catch (Throwable $exception) {
            $session['status'] = 'failed';
            $session['finished_at'] = date('c');
            $session['current_file'] = '';
            $session['runtime_errors'] = isset($session['runtime_errors']) ? (int)$session['runtime_errors'] + 1 : 1;
            $this->store->saveActive($session);
            throw $exception;
        }

        return [
            'success' => true,
            'status' => $session['status'],
            'scan_id' => $session['scan_id'],
            'total_files_estimated' => $session['total_files_estimated'],
            'files_discovered' => $session['files_discovered'],
            'processed_files' => $session['processed_files'],
            'found_total' => $session['found_total'],
            'runtime_errors' => $session['runtime_errors'],
            'batch_size' => $config->getBatchSize(),
            'path' => count($scanPaths) === 1 ? $scanPaths[0] : implode("\n", $scanPaths),
            'scan_paths' => $scanPaths,
            'scan_profile' => $config->getScanProfile(),
        ];
    }

    public function step(string $scanId): array
    {
        $activeSession = $this->store->getActiveSession();

        if ($activeSession !== null && (string)($activeSession['scan_id'] ?? '') !== $scanId) {
            return $this->activeScanConflictPayload($activeSession);
        }

        $session = $this->store->load($scanId);

        if (in_array($session['status'], ['finished', 'cancelled', 'failed'], true)) {
            $this->store->saveActive($session);
            return $this->statusPayload($session);
        }

        $session['status'] = 'running';
        $config = ScanConfig::fromArray($session['config']);
        $session = $this->discoverFilesForStep($session, $config);
        $files = isset($session['files']) && is_array($session['files']) ? $session['files'] : [];
        $cursor = isset($session['cursor']) ? (int)$session['cursor'] : 0;
        $batchSize = $config->getBatchSize();
        $limit = min(count($files), $cursor + $batchSize);
        $stepResults = [];

        for ($index = $cursor; $index < $limit; $index++) {
            $filePath = (string)$files[$index];
            $session['current_file'] = $filePath;
            $result = $this->scanFile($filePath, $config);
            $result = $this->getWhitelistManager()->filterResult($result, $config->getThresholds());
            $result = $this->actionApplier->apply($result, $config, $scanId);
            $session['results'][] = $result;
            $stepResults[] = $result;
            $session['processed_files']++;

            if (!empty($result['findings'])) {
                $session['found_total']++;
            }

            if ($result['status'] === 'error') {
                $session['runtime_errors']++;
            }

            if (isset($result['action_status']) && $result['action_status'] === 'failed') {
                $session['runtime_errors']++;
            }
        }

        $session['cursor'] = $limit;

        if ($session['cursor'] >= count($files) && !empty($session['discovery_done'])) {
            $session = $this->finishSession($session);
        }

        $this->store->saveActive($session);

        return array_merge(
            $this->statusPayload($session),
            [
                'step_results' => $stepResults,
            ]
        );
    }

    public function status(string $scanId): array
    {
        return $this->statusPayload($this->store->load($scanId));
    }

    public function cancel(string $scanId): array
    {
        $activeSession = $this->store->getActiveSession();

        if ($activeSession !== null && (string)($activeSession['scan_id'] ?? '') !== $scanId) {
            return $this->activeScanConflictPayload($activeSession);
        }

        $session = $this->store->load($scanId);

        if (!in_array($session['status'], ['finished', 'cancelled'], true)) {
            $session['status'] = 'cancelled';
            $session['finished_at'] = date('c');
            $session['current_file'] = '';
            $session = $this->saveReportForTerminalSession($session);
            $this->store->saveActive($session);
        } elseif ($session['status'] === 'cancelled' && empty($session['report_path'])) {
            $session = $this->saveReportForTerminalSession($session);
            $this->store->saveActive($session);
        }

        return $this->statusPayload($session);
    }

    public function runToCompletion(ScanConfig $config, int $createdBy = 0, callable $onStep = null): array
    {
        $response = $this->start($config, $createdBy);

        if (empty($response['success'])) {
            return $response;
        }

        $scanId = (string)$response['scan_id'];
        $stepGuard = 0;

        do {
            $response = $this->step($scanId);

            if ($onStep !== null) {
                $onStep($response);
            }

            $stepGuard++;

            if ($stepGuard > 1000000) {
                throw new RuntimeException('scan_iteration_limit_exceeded');
            }
        } while (!empty($response['success']) && ($response['status'] ?? '') === 'running');

        return $response;
    }

    public function validateScanPaths(ScanConfig $config): array
    {
        $paths = [];
        $seen = [];

        foreach ($config->getScanPaths() as $path) {
            try {
                $realPath = $this->validateScanPath($path);
            } catch (RuntimeException $exception) {
                if ($config->ignoresMissingScanPaths() && $exception->getMessage() === 'scan_path_not_found') {
                    continue;
                }

                throw $exception;
            }

            $key = $this->normalizePath($realPath);

            if (!isset($seen[$key])) {
                $paths[] = $realPath;
                $seen[$key] = true;
            }
        }

        if (empty($paths)) {
            throw new RuntimeException('scan_paths_not_found');
        }

        return $paths;
    }

    private function scanFile(string $filePath, ScanConfig $config): array
    {
        try {
            return $this->scanner->scanFile($filePath, $config)->toArray();
        } catch (Throwable $exception) {
            return [
                'file_path' => $filePath,
                'file_hash' => '',
                'status' => 'error',
                'score' => 0,
                'severity' => 'low',
                'findings' => [],
                'action' => 'report',
                'planned_action' => 'report',
                'error' => $exception->getMessage(),
            ];
        }
    }

    private function getWhitelistManager(): WhitelistManager
    {
        if ($this->whitelistManager === null) {
            $this->whitelistManager = new WhitelistManager($this->moduleRoot);
        }

        return $this->whitelistManager;
    }

    private function discoverFilesForStep(array $session, ScanConfig $config): array
    {
        $files = isset($session['files']) && is_array($session['files']) ? array_values($session['files']) : [];
        $cursor = isset($session['cursor']) ? (int)$session['cursor'] : 0;
        $batchSize = $config->getBatchSize();
        $queuedFiles = max(0, count($files) - $cursor);

        if (!empty($session['discovery_done']) || $queuedFiles >= $batchSize) {
            $session['files'] = $files;
            $session = $this->updateDiscoveryTotals($session, count($files));
            return $session;
        }

        $state = isset($session['discovery_state']) && is_array($session['discovery_state'])
            ? $session['discovery_state']
            : $this->createDiscoveryStateFromSession($session, $config);
        $limit = max(1, $batchSize - $queuedFiles);
        $step = $this->collector->collectStep($state, $config, $limit);
        $seen = [];

        foreach ($files as $filePath) {
            $seen[$this->normalizePath((string)$filePath)] = true;
        }

        foreach ($step['files'] as $filePath) {
            $filePath = (string)$filePath;
            $key = $this->normalizePath($filePath);

            if (isset($seen[$key])) {
                continue;
            }

            $files[] = $filePath;
            $seen[$key] = true;
        }

        $session['files'] = $files;
        $session['discovery_state'] = $step['state'];
        $session['discovery_done'] = !empty($step['complete']);
        $session = $this->updateDiscoveryTotals($session, count($files));

        return $session;
    }

    private function updateDiscoveryTotals(array $session, int $filesDiscovered): array
    {
        $session['files_discovered'] = $filesDiscovered;
        $session['total_files_estimated'] = !empty($session['discovery_done']) ? $filesDiscovered : 0;

        return $session;
    }

    private function createDiscoveryStateFromSession(array $session, ScanConfig $config): array
    {
        $files = isset($session['files']) && is_array($session['files']) ? $session['files'] : [];

        if (!empty($files)) {
            return [
                'pending' => [],
                'done' => true,
            ];
        }

        return $this->collector->createDiscoveryState($this->getSessionScanPaths($session, $config));
    }

    private function getSessionScanPaths(array $session, ScanConfig $config): array
    {
        if (isset($session['config']['scan_paths']) && is_array($session['config']['scan_paths'])) {
            $paths = [];

            foreach ($session['config']['scan_paths'] as $path) {
                $path = (string)$path;

                if ($path !== '') {
                    $paths[] = $path;
                }
            }

            if (!empty($paths)) {
                return $paths;
            }
        }

        return $config->getScanPaths();
    }

    private function finishSession(array $session): array
    {
        $session['status'] = 'finished';
        $session['finished_at'] = date('c');
        $session['current_file'] = '';

        return $this->saveReportForTerminalSession($session);
    }

    private function saveReportForTerminalSession(array $session): array
    {
        try {
            $session['report_path'] = $this->reportManager->saveFromSession($session);
        } catch (Throwable $exception) {
            $session['status'] = 'failed';
            $session['runtime_errors'] = isset($session['runtime_errors']) ? (int)$session['runtime_errors'] + 1 : 1;
        }

        return $session;
    }

    private function statusPayload(array $session): array
    {
        $status = (string)$session['status'];
        $discoveryDone = !empty($session['discovery_done']) || in_array($status, ['finished', 'cancelled', 'failed'], true);

        return [
            'success' => true,
            'status' => $status,
            'scan_id' => $session['scan_id'],
            'processed_files' => (int)$session['processed_files'],
            'total_files_estimated' => $discoveryDone ? (int)$session['total_files_estimated'] : 0,
            'files_discovered' => isset($session['files_discovered'])
                ? (int)$session['files_discovered']
                : (isset($session['files']) && is_array($session['files']) ? count($session['files']) : 0),
            'found_total' => (int)$session['found_total'],
            'runtime_errors' => (int)$session['runtime_errors'],
            'current_file' => (string)$session['current_file'],
            'cursor' => (int)$session['cursor'],
            'report_path' => (string)$session['report_path'],
            'discovery_done' => $discoveryDone,
        ];
    }

    private function activeScanConflictPayload(array $activeSession): array
    {
        $scanId = (string)($activeSession['scan_id'] ?? '');
        $discoveryDone = !empty($activeSession['discovery_done']);

        return [
            'success' => false,
            'status' => (string)($activeSession['status'] ?? 'running'),
            'error' => 'scan_already_running',
            'scan_id' => $scanId,
            'active_scan_id' => $scanId,
            'processed_files' => (int)($activeSession['processed_files'] ?? 0),
            'total_files_estimated' => $discoveryDone ? (int)($activeSession['total_files_estimated'] ?? 0) : 0,
            'files_discovered' => (int)($activeSession['files_discovered'] ?? 0),
            'found_total' => (int)($activeSession['found_total'] ?? 0),
            'runtime_errors' => (int)($activeSession['runtime_errors'] ?? 0),
            'current_file' => (string)($activeSession['current_file'] ?? ''),
            'discovery_done' => $discoveryDone,
        ];
    }

    private function validateScanPath(string $path): string
    {
        $realPath = realpath($path);

        if ($realPath === false) {
            throw new RuntimeException('scan_path_not_found');
        }

        $realDocumentRoot = realpath($this->documentRoot);

        if ($realDocumentRoot === false) {
            throw new RuntimeException('document_root_not_found');
        }

        $normalizedPath = $this->normalizePath($realPath);
        $normalizedDocumentRoot = $this->normalizePath($realDocumentRoot);

        if ($normalizedPath !== $normalizedDocumentRoot && strpos($normalizedPath, $normalizedDocumentRoot . '/') !== 0) {
            throw new RuntimeException('scan_path_outside_document_root');
        }

        return $realPath;
    }

    private function normalizePath(string $path): string
    {
        return str_replace('\\', '/', strtolower(rtrim($path, '/\\')));
    }
}
