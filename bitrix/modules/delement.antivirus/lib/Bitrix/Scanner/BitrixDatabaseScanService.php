<?php

namespace Delement\Antivirus\Bitrix\Scanner;

use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\Scanner\ScanResult;
use Throwable;

class BitrixDatabaseScanService
{
    private $agentScanner;
    private $eventHandlerScanner;

    public function __construct(AgentScanner $agentScanner = null, EventHandlerScanner $eventHandlerScanner = null)
    {
        $this->agentScanner = $agentScanner ?: new AgentScanner();
        $this->eventHandlerScanner = $eventHandlerScanner;
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

        if ($config->isEventHandlerScanEnabled()) {
            try {
                foreach ($this->getEventHandlerScanner()->scan($config) as $result) {
                    if ($result instanceof ScanResult) {
                        $results[] = $result->toArray();
                    }
                }
            } catch (Throwable $exception) {
                return $results;
            }
        }

        return $results;
    }

    private function getEventHandlerScanner(): EventHandlerScanner
    {
        if ($this->eventHandlerScanner === null) {
            $this->eventHandlerScanner = new EventHandlerScanner();
        }

        return $this->eventHandlerScanner;
    }
}
