<?php

namespace Delement\Antivirus\Bitrix\Scanner;

use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\Detection\Ast\AstAnalyzer;
use Delement\Antivirus\Detection\Entropy\EntropyAnalyzer;
use Delement\Antivirus\Detection\Finding;
use Delement\Antivirus\Detection\RuleEngine;
use Delement\Antivirus\Detection\SignatureLoader;
use Delement\Antivirus\Detection\Url\UrlAnalyzer;

class VirtualCodeScanner
{
    private $signatureLoader;
    private $ruleEngines = [];
    private $astAnalyzer;
    private $entropyAnalyzer;
    private $urlAnalyzer;

    public function __construct(
        SignatureLoader $signatureLoader = null,
        AstAnalyzer $astAnalyzer = null,
        EntropyAnalyzer $entropyAnalyzer = null,
        UrlAnalyzer $urlAnalyzer = null
    ) {
        $this->signatureLoader = $signatureLoader ?: new SignatureLoader();
        $this->astAnalyzer = $astAnalyzer ?: (class_exists(AstAnalyzer::class) ? new AstAnalyzer() : null);
        $this->entropyAnalyzer = $entropyAnalyzer ?: (class_exists(EntropyAnalyzer::class) ? new EntropyAnalyzer() : null);
        $this->urlAnalyzer = $urlAnalyzer ?: (class_exists(UrlAnalyzer::class) ? new UrlAnalyzer() : null);
    }

    public function analyze(string $code, string $virtualPath, ScanConfig $config): array
    {
        $findings = [];
        $seen = [];
        $analysisPath = $virtualPath . '.php';

        foreach ($this->ruleEngine($config)->analyzeContent($code, $analysisPath, $config) as $finding) {
            $this->addFinding($findings, $seen, $finding);
        }

        if ($config->isAstAnalysisEnabled() && $this->astAnalyzer !== null && strlen($code) <= $config->getAstMaxFileSize()) {
            foreach ($this->astAnalyzer->analyze($code, $virtualPath) as $finding) {
                $this->addFinding($findings, $seen, $finding);
            }
        }

        if ($config->isEntropyAnalyzerEnabled() && $this->entropyAnalyzer !== null) {
            foreach ($this->entropyAnalyzer->analyze($code, $virtualPath, $config) as $finding) {
                $this->addFinding($findings, $seen, $finding);
            }
        }

        if ($config->isUrlAnalyzerEnabled() && $this->urlAnalyzer !== null) {
            foreach ($this->urlAnalyzer->analyze($code, $virtualPath, $config) as $finding) {
                $this->addFinding($findings, $seen, $finding);
            }
        }

        return $findings;
    }

    private function ruleEngine(ScanConfig $config): RuleEngine
    {
        $signaturesPath = $config->getSignaturesPath();
        $cacheKey = $signaturesPath !== '' ? $signaturesPath : '__default__';

        if (!isset($this->ruleEngines[$cacheKey])) {
            $rules = $this->signatureLoader->loadDefaultRules();

            if ($signaturesPath !== '') {
                $rules = array_merge($rules, $this->signatureLoader->loadFromFile($signaturesPath));
            }

            $this->ruleEngines[$cacheKey] = new RuleEngine($rules);
        }

        return $this->ruleEngines[$cacheKey];
    }

    private function addFinding(array &$findings, array &$seen, $finding): void
    {
        if (!$finding instanceof Finding) {
            return;
        }

        $data = $finding->toArray();
        $key = implode(':', [
            (string)($data['signature_id'] ?? ''),
            (string)($data['target'] ?? ''),
            (string)($data['rule_type'] ?? ''),
            (string)($data['offset'] ?? ''),
            sha1((string)($data['excerpt'] ?? '')),
        ]);

        if (isset($seen[$key])) {
            return;
        }

        $findings[] = $finding;
        $seen[$key] = true;
    }
}
