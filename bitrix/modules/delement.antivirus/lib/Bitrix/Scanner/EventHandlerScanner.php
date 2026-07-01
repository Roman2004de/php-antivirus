<?php

namespace Delement\Antivirus\Bitrix\Scanner;

use Delement\Antivirus\Bitrix\Database\BitrixDb;
use Delement\Antivirus\Bitrix\Resolver\EventHandlerResolver;
use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\Detection\Finding;
use Delement\Antivirus\Detection\Severity;
use Delement\Antivirus\Detection\Tags\ResultTagger;
use Delement\Antivirus\Detection\Verdict;
use Delement\Antivirus\Scanner\Scanner;
use Delement\Antivirus\Scanner\ScanResult;
use Throwable;

class EventHandlerScanner
{
    private $db;
    private $resolver;
    private $riskAnalyzer;
    private $fileScanner;
    private $factory;
    private $resultTagger;

    public function __construct(
        BitrixDb $db = null,
        EventHandlerResolver $resolver = null,
        EventHandlerRiskAnalyzer $riskAnalyzer = null,
        Scanner $fileScanner = null,
        BitrixDbFindingFactory $factory = null,
        ResultTagger $resultTagger = null
    ) {
        $this->db = $db ?: new BitrixDb();
        $this->resolver = $resolver ?: new EventHandlerResolver();
        $this->factory = $factory ?: new BitrixDbFindingFactory();
        $this->riskAnalyzer = $riskAnalyzer ?: new EventHandlerRiskAnalyzer($this->db, $this->factory);
        $this->fileScanner = $fileScanner ?: new Scanner();
        $this->resultTagger = $resultTagger ?: (class_exists(ResultTagger::class) ? new ResultTagger() : null);
    }

    public function scan(ScanConfig $config): array
    {
        if (!$config->isBitrixDbScanEnabled() || !$config->isEventHandlerScanEnabled()) {
            return [];
        }

        if (!$this->db->isAvailable() || !$this->db->tableExists('b_module_to_module')) {
            return [];
        }

        try {
            $eventHandlers = $this->db->fetchEventHandlers();
        } catch (Throwable $exception) {
            return [];
        }

        $results = [];

        foreach ($eventHandlers as $eventHandler) {
            if (!is_array($eventHandler)) {
                continue;
            }

            $result = $this->scanEventHandler($eventHandler, $config);

            if ($result !== null) {
                $results[] = $result;
            }
        }

        return $results;
    }

    private function scanEventHandler(array $eventHandler, ScanConfig $config): ?ScanResult
    {
        $virtualPath = $this->factory->virtualEventPath($eventHandler);
        $findings = $this->riskAnalyzer->analyze($eventHandler);

        if ($config->isEventHandlerCodeResolveEnabled()) {
            foreach ($this->resolveFiles($eventHandler, $config->getDocumentRoot()) as $filePath) {
                foreach ($this->findingsForResolvedFile($eventHandler, $filePath, $config) as $finding) {
                    $findings[] = $finding;
                }
            }
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
            null,
            $config->getDocumentRoot()
        );
    }

    private function resolveFiles(array $eventHandler, string $documentRoot): array
    {
        try {
            return $this->resolver->resolve($eventHandler, $documentRoot);
        } catch (Throwable $exception) {
            return [];
        }
    }

    private function findingsForResolvedFile(array $eventHandler, string $filePath, ScanConfig $config): array
    {
        try {
            $scanResult = $this->fileScanner->scanFile($filePath, $config)->toArray();
        } catch (Throwable $exception) {
            return [];
        }

        $detectorFindings = $this->riskFindings($scanResult['findings'] ?? []);

        if (empty($detectorFindings)) {
            return [];
        }

        $findings = [
            $this->factory->eventHandlerFileSuspicious($eventHandler, $filePath, $detectorFindings),
        ];

        foreach ($detectorFindings as $detectorFinding) {
            if ($this->isRequestToSinkFinding($detectorFinding)) {
                $findings[] = $this->factory->eventRequestToSink($eventHandler, $this->sinkName($detectorFinding), $filePath);
                break;
            }
        }

        return $findings;
    }

    private function riskFindings($findings): array
    {
        if (!is_array($findings)) {
            return [];
        }

        $result = [];

        foreach ($findings as $finding) {
            if (is_array($finding) && (int)($finding['score'] ?? 0) > 0) {
                $result[] = $finding;
            }
        }

        return $result;
    }

    private function isRequestToSinkFinding(array $finding): bool
    {
        $category = strtolower((string)($finding['category'] ?? ''));
        $signatureId = strtolower((string)($finding['signature_id'] ?? ''));

        if ($category === 'taint' || $category === 'php_taint' || strpos($signatureId, 'request') !== false) {
            return true;
        }

        $excerpt = (string)($finding['excerpt'] ?? '');

        if (
            preg_match('/\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b/i', $excerpt) === 1
            && preg_match('/(eval|assert|system|exec|shell_exec|passthru|proc_open|popen|include|require|file_put_contents|fwrite)/i', $signatureId . ' ' . $excerpt) === 1
        ) {
            return true;
        }

        return $this->traceContainsRequestSource($finding['trace'] ?? null);
    }

    private function traceContainsRequestSource($trace): bool
    {
        if (!is_array($trace)) {
            return false;
        }

        $source = isset($trace['source']) ? (string)$trace['source'] : '';

        if ($source !== '' && preg_match('/\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b/i', $source) === 1) {
            return true;
        }

        foreach ($trace as $value) {
            if (is_array($value) && $this->traceContainsRequestSource($value)) {
                return true;
            }
        }

        return false;
    }

    private function sinkName(array $finding): string
    {
        if (isset($finding['trace']['sink'])) {
            return (string)$finding['trace']['sink'];
        }

        $signatureId = (string)($finding['signature_id'] ?? '');

        if (preg_match('/(?:request_to_|dangerous_call_)([a-zA-Z0-9_]+)/', $signatureId, $match) === 1) {
            return strtolower((string)$match[1]);
        }

        return $signatureId !== '' ? $signatureId : 'unknown';
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
                (string)($data['trace']['resolved_file'] ?? ''),
                (string)($data['trace']['risk_reason'] ?? ''),
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
}
