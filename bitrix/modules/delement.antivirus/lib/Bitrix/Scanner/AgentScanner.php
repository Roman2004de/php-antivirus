<?php

namespace Delement\Antivirus\Bitrix\Scanner;

use Delement\Antivirus\Bitrix\Database\BitrixDb;
use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\Detection\Finding;
use Delement\Antivirus\Detection\Severity;
use Delement\Antivirus\Detection\Tags\ResultTagger;
use Delement\Antivirus\Detection\Verdict;
use Delement\Antivirus\Scanner\ScanResult;
use Throwable;

class AgentScanner
{
    private $db;
    private $virtualScanner;
    private $factory;
    private $resultTagger;

    public function __construct(
        BitrixDb $db = null,
        VirtualCodeScanner $virtualScanner = null,
        BitrixDbFindingFactory $factory = null,
        ResultTagger $resultTagger = null
    ) {
        $this->db = $db ?: new BitrixDb();
        $this->virtualScanner = $virtualScanner ?: new VirtualCodeScanner();
        $this->factory = $factory ?: new BitrixDbFindingFactory();
        $this->resultTagger = $resultTagger ?: (class_exists(ResultTagger::class) ? new ResultTagger() : null);
    }

    public function scan(ScanConfig $config): array
    {
        if (!$config->isBitrixDbScanEnabled() || !$config->isAgentScanEnabled()) {
            return [];
        }

        if (!$this->db->isAvailable() || !$this->db->tableExists('b_agent')) {
            return [];
        }

        try {
            $agents = $this->db->fetchAgents();
        } catch (Throwable $exception) {
            return [];
        }

        $results = [];

        foreach ($agents as $agent) {
            if (!is_array($agent)) {
                continue;
            }

            $result = $this->scanAgent($agent, $config);

            if ($result !== null) {
                $results[] = $result;
            }
        }

        return $results;
    }

    private function scanAgent(array $agent, ScanConfig $config): ?ScanResult
    {
        $name = (string)($agent['NAME'] ?? '');

        if (trim($name) === '') {
            return null;
        }

        $virtualPath = $this->factory->virtualAgentPath($agent);
        $code = "<?php\n" . rtrim($name) . ";\n";
        $findings = [];

        foreach ($this->virtualScanner->analyze($code, $virtualPath, $config) as $finding) {
            if ($finding instanceof Finding) {
                $findings[] = $this->factory->decorateDetectorFinding($finding, $agent);
            }
        }

        foreach ($this->heuristicFindings($agent, $name) as $finding) {
            $findings[] = $finding;
        }

        $findings = $this->deduplicateFindings($findings);

        if (empty($findings)) {
            return null;
        }

        if ($this->resultTagger !== null) {
            $findings = $this->resultTagger->tagFindings($findings);
            $tags = $this->resultTagger->tagsForResult($virtualPath, $findings);
        } else {
            $tags = [];
        }

        $score = 0;
        $severity = Severity::INFO;

        foreach ($findings as $finding) {
            if (!$finding instanceof Finding) {
                continue;
            }

            $score += $finding->getScore();
            $severity = Severity::max($severity, $finding->getSeverity());
        }

        return ScanResult::fromFindings(
            $virtualPath,
            Verdict::fromScore($score, $config->getThresholds()),
            $score,
            $severity,
            $findings,
            ScanConfig::ACTION_REPORT,
            true,
            $tags,
            $config->isNormalizedHashEnabled() ? $this->normalizedHash($code) : null,
            $config->getDocumentRoot()
        );
    }

    private function heuristicFindings(array $agent, string $name): array
    {
        $findings = [];
        $seen = [];

        if (strlen($name) > 500) {
            $this->addHeuristicFinding($findings, $seen, $this->factory->suspiciousLongCode($agent, $name));
        }

        $moduleId = trim((string)($agent['MODULE_ID'] ?? ''));

        if ($moduleId === '') {
            $this->addHeuristicFinding($findings, $seen, $this->factory->unknownModule($agent, $name, 'empty_module_id'));
        } else {
            $installed = $this->db->isModuleInstalled($moduleId);

            if ($installed === false) {
                $this->addHeuristicFinding($findings, $seen, $this->factory->unknownModule($agent, $name, 'module_not_installed'));
            }
        }

        if (preg_match('/\b(base64_decode|gzinflate|gzuncompress|str_rot13|chr|pack)\s*\(/i', $name, $match) === 1) {
            $this->addHeuristicFinding($findings, $seen, $this->factory->encodedPayload($agent, $name, strtolower($match[1])));
        }

        if (preg_match('/\b(eval|assert|create_function|system|exec|shell_exec|passthru|proc_open)\s*\(/i', $name, $match) === 1) {
            $this->addHeuristicFinding($findings, $seen, $this->factory->dangerousExecution($agent, $name, strtolower($match[1])));
        }

        if (preg_match('/\b(include|include_once|require|require_once)\s*\(?\s*\$/i', $name) === 1) {
            $this->addHeuristicFinding($findings, $seen, $this->factory->dangerousExecution($agent, $name, 'dynamic_include'));
        }

        if (
            preg_match('/\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b/i', $name) === 1
            && preg_match('/\b(eval|assert|system|exec|shell_exec|passthru|proc_open|popen|include|include_once|require|require_once|call_user_func|call_user_func_array)\b/i', $name, $match) === 1
        ) {
            $this->addHeuristicFinding($findings, $seen, $this->factory->requestToSink($agent, $name, strtolower($match[1])));
        }

        if (preg_match('#https?://[^\s\'")<>]+#i', $name, $match) === 1) {
            $this->addHeuristicFinding($findings, $seen, $this->factory->remoteLoader($agent, $name, (string)$match[0]));
        }

        if (preg_match('/\b(file_put_contents|fopen|fwrite)\s*\(/i', $name, $match) === 1) {
            $this->addHeuristicFinding($findings, $seen, $this->factory->fileWrite($agent, $name, strtolower($match[1])));
        }

        return $findings;
    }

    private function addHeuristicFinding(array &$findings, array &$seen, Finding $finding): void
    {
        $signatureId = $finding->getSignatureId();

        if ($signatureId !== '' && isset($seen[$signatureId])) {
            return;
        }

        $findings[] = $finding;
        $seen[$signatureId] = true;
    }

    private function deduplicateFindings(array $findings): array
    {
        $result = [];
        $seen = [];

        foreach ($findings as $finding) {
            if (!$finding instanceof Finding) {
                continue;
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
                continue;
            }

            $result[] = $finding;
            $seen[$key] = true;
        }

        return $result;
    }

    private function normalizedHash(string $code): string
    {
        $normalized = preg_replace('/\s+/', '', $code);

        return hash('sha256', $normalized === null ? $code : $normalized);
    }
}
