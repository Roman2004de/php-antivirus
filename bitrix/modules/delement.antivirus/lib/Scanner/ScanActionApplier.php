<?php

namespace Delement\Antivirus\Scanner;

use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\Quarantine\QuarantineManager;
use RuntimeException;

class ScanActionApplier
{
    private $documentRoot;

    public function __construct(string $documentRoot)
    {
        $this->documentRoot = rtrim($documentRoot, '/\\');
    }

    public function apply(array $result, ScanConfig $config, string $scanId): array
    {
        $hasFindings = isset($result['findings']) && is_array($result['findings']) && !empty($result['findings']);
        $plannedAction = $config->getAction();

        if (!$hasFindings) {
            return $result;
        }

        $result['planned_action'] = $plannedAction;

        if ($plannedAction === ScanConfig::ACTION_REPORT) {
            $result['action'] = ScanConfig::ACTION_REPORT;
            $result['action_status'] = 'reported';
            return $result;
        }

        if ($config->isDryRun()) {
            $result['action'] = ScanConfig::ACTION_REPORT;
            $result['action_status'] = 'dry_run';
            return $result;
        }

        if ($plannedAction === ScanConfig::ACTION_QUARANTINE) {
            return $this->applyQuarantine($result, $config, $scanId);
        }

        if ($plannedAction === ScanConfig::ACTION_DELETE) {
            return $this->applyDelete($result, $config, $scanId);
        }

        $result['action'] = ScanConfig::ACTION_REPORT;
        $result['action_status'] = 'unsupported';

        return $result;
    }

    private function applyQuarantine(array $result, ScanConfig $config, string $scanId): array
    {
        try {
            $quarantine = new QuarantineManager($config->getQuarantinePath(), $this->documentRoot);
            $item = $quarantine->quarantine((string)($result['file_path'] ?? ''), $result, $scanId);

            $result['action'] = ScanConfig::ACTION_QUARANTINE;
            $result['action_status'] = 'done';
            $result['quarantine_id'] = (string)$item['id'];
            $result['quarantined_at'] = (string)$item['quarantined_at'];
        } catch (RuntimeException $exception) {
            $result['action'] = ScanConfig::ACTION_REPORT;
            $result['action_status'] = 'failed';
            $result['action_error'] = $exception->getMessage();
        }

        return $result;
    }

    private function applyDelete(array $result, ScanConfig $config, string $scanId): array
    {
        try {
            $quarantine = new QuarantineManager($config->getQuarantinePath(), $this->documentRoot);
            $item = $quarantine->deleteOriginal((string)($result['file_path'] ?? ''), $result, $scanId);

            $result['action'] = ScanConfig::ACTION_DELETE;
            $result['action_status'] = 'done';
            $result['delete_id'] = (string)$item['id'];
            $result['quarantine_id'] = (string)$item['id'];
            $result['deleted_at'] = (string)$item['deleted_at'];
        } catch (RuntimeException $exception) {
            $result['action'] = ScanConfig::ACTION_REPORT;
            $result['action_status'] = 'failed';
            $result['action_error'] = $exception->getMessage();
        }

        return $result;
    }
}
