<?php

namespace Delement\Antivirus\Detection;

use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\Scanner\ScanResult;

class Detector
{
    private $ruleEngine;

    public function __construct(RuleEngine $ruleEngine)
    {
        $this->ruleEngine = $ruleEngine;
    }

    public function detect(string $filePath, iterable $chunks, ScanConfig $config): ScanResult
    {
        $findings = [];
        $seen = [];

        foreach ($this->ruleEngine->analyzePath($filePath, $config) as $finding) {
            $this->addFinding($findings, $seen, $finding);
        }

        foreach ($chunks as $chunk) {
            foreach ($this->ruleEngine->analyzeContent((string)$chunk, $filePath, $config) as $finding) {
                $this->addFinding($findings, $seen, $finding);
            }
        }

        $score = 0;
        $severity = Severity::INFO;

        foreach ($findings as $finding) {
            $score += $finding->getScore();
            $severity = Severity::max($severity, $finding->getSeverity());
        }

        $verdict = Verdict::fromScore($score, $config->getThresholds());

        return ScanResult::fromFindings($filePath, $verdict, $score, $severity, $findings, $config->getAction(), $config->isDryRun());
    }

    private function addFinding(array &$findings, array &$seen, Finding $finding): void
    {
        $id = $finding->getSignatureId();

        if ($id !== '' && isset($seen[$id])) {
            return;
        }

        $findings[] = $finding;

        if ($id !== '') {
            $seen[$id] = true;
        }
    }
}
