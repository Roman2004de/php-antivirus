<?php

namespace Delement\Antivirus\Bitrix\Scanner;

use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\Scanner\ScanResult;
use Throwable;

class BitrixDatabaseScanService
{
    private $agentScanner;

    public function __construct(AgentScanner $agentScanner = null)
    {
        $this->agentScanner = $agentScanner ?: new AgentScanner();
    }

    public function scan(ScanConfig $config): array
    {
        if (!$config->isBitrixDbScanEnabled()) {
            return [];
        }

        $results = [];

        if ($config->isAgentScanEnabled()) {
            try {
                foreach ($this->agentScanner->scan($config) as $result) {
                    if ($result instanceof ScanResult) {
                        $results[] = $result->toArray();
                    }
                }
            } catch (Throwable $exception) {
                return [];
            }
        }

        return $results;
    }
}
