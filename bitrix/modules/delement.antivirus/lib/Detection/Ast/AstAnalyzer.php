<?php

namespace Delement\Antivirus\Detection\Ast;

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

    public function analyze(string $content): array
    {
        $parseResult = $this->parser->parse($content);

        if (!$parseResult->isSuccess()) {
            return [];
        }

        $context = $this->collector->collect($parseResult->getNodes());

        return array_merge(
            $this->dangerousCallDetector->detect($context),
            $this->dynamicCallDetector->detect($context),
            $this->encodedPayloadDetector->detect($context),
            $this->taintAnalyzer->analyze($context)
        );
    }
}
