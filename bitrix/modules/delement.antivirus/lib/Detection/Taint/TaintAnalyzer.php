<?php

namespace Delement\Antivirus\Detection\Taint;

use Delement\Antivirus\Detection\Ast\AstContext;

class TaintAnalyzer
{
    private $propagator;
    private $sinkDetector;

    public function __construct(TaintPropagator $propagator = null, TaintSinkDetector $sinkDetector = null)
    {
        $this->propagator = $propagator ?: new TaintPropagator();
        $this->sinkDetector = $sinkDetector ?: new TaintSinkDetector($this->propagator);
    }

    public function analyze(AstContext $context): array
    {
        $taints = $this->propagator->build($context);

        return $this->sinkDetector->detect($context, $taints);
    }
}
