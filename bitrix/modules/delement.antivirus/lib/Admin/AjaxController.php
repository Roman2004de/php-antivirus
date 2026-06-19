<?php

namespace Delement\Antivirus\Admin;

use Bitrix\Main\Config\Option;
use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\Report\ReportManager;
use Delement\Antivirus\Scanner\ScanActionApplier;
use Delement\Antivirus\Scanner\ScanRunService;
use Delement\Antivirus\Scanner\ScanSessionStore;
use Delement\Antivirus\Support\ModuleVersion;
use InvalidArgumentException;

class AjaxController
{
    private $moduleId;
    private $documentRoot;
    private $store;
    private $reportManager;
    private $scanRunService;
    private $moduleRoot;

    public function __construct(
        string $moduleId,
        string $documentRoot,
        ScanSessionStore $store = null,
        ReportManager $reportManager = null,
        string $moduleRoot = null
    )
    {
        $this->moduleId = $moduleId;
        $this->documentRoot = rtrim($documentRoot, '/\\');
        $this->moduleRoot = $moduleRoot ?: dirname(__DIR__, 2);
        $this->store = $store ?: new ScanSessionStore();
        $this->reportManager = $reportManager ?: new ReportManager();
        $this->scanRunService = new ScanRunService($this->documentRoot, $this->store, $this->reportManager, $this->moduleRoot);
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
            'version' => ModuleVersion::version($this->moduleRoot),
            'status' => 'engine_ready',
        ];
    }

    private function startScan(int $userId): array
    {
        $config = $this->createConfigFromOptions();

        return $this->scanRunService->start($config, $userId);
    }

    private function scanStep(string $scanId): array
    {
        return $this->scanRunService->step($scanId);
    }

    private function getStatus(string $scanId): array
    {
        return $this->scanRunService->status($scanId);
    }

    private function cancelScan(string $scanId): array
    {
        return $this->scanRunService->cancel($scanId);
    }

    private function applyConfiguredAction(array $result, ScanConfig $config, string $scanId): array
    {
        return (new ScanActionApplier($this->documentRoot))->apply($result, $config, $scanId);
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

    private function getScanId(array $request): string
    {
        $scanId = isset($request['scan_id']) ? (string)$request['scan_id'] : '';

        if ($scanId === '') {
            throw new InvalidArgumentException('scan_id_required');
        }

        return $scanId;
    }
}
