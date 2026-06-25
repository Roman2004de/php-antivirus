<?php

namespace Delement\Antivirus\Detection\Ast;

use Delement\Antivirus\Detection\Finding;
use Delement\Antivirus\Detection\Taint\TaintAnalyzer;

class AstAnalyzer
{
    private $parser;
    private $collector;
    private $dangerousCallDetector;
    private $dynamicCallDetector;
    private $encodedPayloadDetector;
    private $taintAnalyzer;

    public function __construct(
        PhpAstParser $parser = null,
        NodeCollector $collector = null,
        DangerousCallDetector $dangerousCallDetector = null,
        DynamicCallDetector $dynamicCallDetector = null,
        EncodedPayloadDetector $encodedPayloadDetector = null,
        TaintAnalyzer $taintAnalyzer = null
    ) {
        $factory = new AstFindingFactory();
        $this->parser = $parser ?: new PhpAstParser();
        $this->collector = $collector ?: new NodeCollector();
        $this->dangerousCallDetector = $dangerousCallDetector ?: new DangerousCallDetector($factory);
        $this->dynamicCallDetector = $dynamicCallDetector ?: new DynamicCallDetector($factory);
        $this->encodedPayloadDetector = $encodedPayloadDetector ?: new EncodedPayloadDetector($factory);
        $this->taintAnalyzer = $taintAnalyzer ?: new TaintAnalyzer();
    }

    public function analyze(string $content, string $filePath): array
    {
        $parseResult = $this->parser->parse($content);

        if (!$parseResult->isSuccess()) {
            return [];
        }

        $context = $this->collector->collect($parseResult->getNodes());

        $findings = array_merge(
            $this->dangerousCallDetector->detect($context),
            $this->dynamicCallDetector->detect($context),
            $this->encodedPayloadDetector->detect($context),
            $this->taintAnalyzer->analyze($context)
        );

        return $this->enrichFindings($findings, $filePath);
    }

    private function enrichFindings(array $findings, string $filePath): array
    {
        $enriched = [];

        foreach ($findings as $finding) {
            if (!$finding instanceof Finding) {
                continue;
            }

            $data = $finding->toArray();
            $data['file'] = $filePath;
            $line = $this->findingLine($data);

            if ($line > 0) {
                $data['line'] = $line;
            }

            $data['type'] = isset($data['rule_type']) ? (string)$data['rule_type'] : 'ast';
            $data['source'] = $this->findingSource($data);
            $enriched[] = new Finding($data);
        }

        return $enriched;
    }

    private function findingLine(array $finding): int
    {
        if (isset($finding['offset']) && (int)$finding['offset'] > 0) {
            return (int)$finding['offset'];
        }

        if (isset($finding['trace']['sink_line']) && (int)$finding['trace']['sink_line'] > 0) {
            return (int)$finding['trace']['sink_line'];
        }

        if (isset($finding['trace']['source_line']) && (int)$finding['trace']['source_line'] > 0) {
            return (int)$finding['trace']['source_line'];
        }

        return 0;
    }

    private function findingSource(array $finding): string
    {
        if (isset($finding['trace']['source'])) {
            return (string)$finding['trace']['source'];
        }

        if (($finding['rule_type'] ?? '') === 'taint') {
            return 'taint';
        }

        return 'ast';
    }
}
