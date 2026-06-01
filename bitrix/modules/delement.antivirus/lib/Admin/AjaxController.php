<?php

namespace Delement\Antivirus\Admin;

use Bitrix\Main\Config\Option;
use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\File\FileCollector;
use Delement\Antivirus\Scanner\Scanner;
use Delement\Antivirus\Scanner\ScanSessionStore;
use InvalidArgumentException;
use RuntimeException;
use Throwable;

class AjaxController
{
    private $moduleId;
    private $documentRoot;
    private $store;

    public function __construct(string $moduleId, string $documentRoot, ScanSessionStore $store = null)
    {
        $this->moduleId = $moduleId;
        $this->documentRoot = rtrim($documentRoot, '/\\');
        $this->store = $store ?: new ScanSessionStore();
    }

    public function handle(string $action, array $request, int $userId = 0): array
    {
        switch ($action) {
            case 'ping':
                return $this->ping();
            case 'start_scan':
                return $this->startScan($userId);
            case 'scan_step':
                return $this->scanStep($this->getScanId($request));
            case 'get_status':
                return $this->getStatus($this->getScanId($request));
            case 'cancel_scan':
                return $this->cancelScan($this->getScanId($request));
        }

        throw new InvalidArgumentException('unknown_action');
    }

    private function ping(): array
    {
        return [
            'success' => true,
            'module' => $this->moduleId,
            'version' => '0.0.1',
            'status' => 'engine_ready',
        ];
    }

    private function startScan(int $userId): array
    {
        $config = $this->createConfigFromOptions();
        $scanPath = $this->validateScanPath($config->getPath());

        $files = [];
        $collector = new FileCollector();

        foreach ($collector->collect($scanPath, $config) as $filePath) {
            $files[] = (string)$filePath;
        }

        $session = $this->store->create($config, $files, $userId);
        $session['status'] = 'running';
        $this->store->save($session);

        return [
            'success' => true,
            'status' => $session['status'],
            'scan_id' => $session['scan_id'],
            'total_files_estimated' => $session['total_files_estimated'],
            'processed_files' => $session['processed_files'],
            'found_total' => $session['found_total'],
            'runtime_errors' => $session['runtime_errors'],
            'batch_size' => $config->getBatchSize(),
            'path' => $scanPath,
        ];
    }

    private function scanStep(string $scanId): array
    {
        $session = $this->store->load($scanId);

        if (in_array($session['status'], ['finished', 'cancelled', 'failed'], true)) {
            return $this->statusPayload($session);
        }

        $session['status'] = 'running';
        $config = ScanConfig::fromArray($session['config']);
        $scanner = new Scanner();
        $files = isset($session['files']) && is_array($session['files']) ? $session['files'] : [];
        $cursor = isset($session['cursor']) ? (int)$session['cursor'] : 0;
        $batchSize = $config->getBatchSize();
        $limit = min(count($files), $cursor + $batchSize);
        $stepResults = [];

        for ($index = $cursor; $index < $limit; $index++) {
            $filePath = (string)$files[$index];
            $session['current_file'] = $filePath;

            try {
                $result = $scanner->scanFile($filePath, $config)->toArray();
            } catch (Throwable $exception) {
                $result = [
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

            $session['results'][] = $result;
            $stepResults[] = $result;
            $session['processed_files']++;

            if (!empty($result['findings'])) {
                $session['found_total']++;
            }

            if ($result['status'] === 'error') {
                $session['runtime_errors']++;
            }
        }

        $session['cursor'] = $limit;

        if ($session['cursor'] >= count($files)) {
            $session['status'] = 'finished';
            $session['finished_at'] = date('c');
            $session['current_file'] = '';
            $session['report_path'] = $this->store->saveReport($session);
        }

        $this->store->save($session);

        return array_merge(
            $this->statusPayload($session),
            [
                'step_results' => $stepResults,
            ]
        );
    }

    private function getStatus(string $scanId): array
    {
        return $this->statusPayload($this->store->load($scanId));
    }

    private function cancelScan(string $scanId): array
    {
        $session = $this->store->load($scanId);

        if (!in_array($session['status'], ['finished', 'cancelled'], true)) {
            $session['status'] = 'cancelled';
            $session['finished_at'] = date('c');
            $session['current_file'] = '';
            $this->store->save($session);
        }

        return $this->statusPayload($session);
    }

    private function statusPayload(array $session): array
    {
        return [
            'success' => true,
            'status' => $session['status'],
            'scan_id' => $session['scan_id'],
            'processed_files' => (int)$session['processed_files'],
            'total_files_estimated' => (int)$session['total_files_estimated'],
            'found_total' => (int)$session['found_total'],
            'runtime_errors' => (int)$session['runtime_errors'],
            'current_file' => (string)$session['current_file'],
            'cursor' => (int)$session['cursor'],
            'report_path' => (string)$session['report_path'],
        ];
    }

    private function createConfigFromOptions(): ScanConfig
    {
        $defaults = $this->loadDefaults();
        $options = [];

        foreach ($defaults as $name => $defaultValue) {
            $options[$name] = Option::get($this->moduleId, $name, (string)$defaultValue);
        }

        return ScanConfig::fromModuleOptions($options, $this->documentRoot);
    }

    private function loadDefaults(): array
    {
        $path = dirname(__DIR__, 2) . '/default_option.php';
        $delement_antivirus_default_option = [];

        if (is_file($path)) {
            require $path;
        }

        return is_array($delement_antivirus_default_option) ? $delement_antivirus_default_option : [];
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

        if (strpos($normalizedPath, $normalizedDocumentRoot) !== 0) {
            throw new RuntimeException('scan_path_outside_document_root');
        }

        return $realPath;
    }

    private function getScanId(array $request): string
    {
        $scanId = isset($request['scan_id']) ? (string)$request['scan_id'] : '';

        if ($scanId === '') {
            throw new InvalidArgumentException('scan_id_required');
        }

        return $scanId;
    }

    private function normalizePath(string $path): string
    {
        return str_replace('\\', '/', strtolower(rtrim($path, '/\\')));
    }
}
