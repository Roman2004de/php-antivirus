<?php

namespace Delement\Antivirus\Detection\Taint;

use Delement\Antivirus\Detection\Finding;
use Delement\Antivirus\Detection\Severity;

class TaintFindingFactory
{
    public function create(TaintTrace $trace): Finding
    {
        $sink = strtolower($trace->getSink());
        $signatureSink = preg_replace('/[^a-z0-9_]+/', '_', $sink);
        $severity = $trace->getSeverity() === Severity::HIGH ? Severity::HIGH : Severity::CRITICAL;

        return new Finding([
            'signature_id' => 'taint_request_to_' . $signatureSink,
            'name' => 'Taint: request data reaches ' . $sink,
            'category' => 'php_taint',
            'severity' => $severity,
            'score' => $trace->getScore(),
            'offset' => null,
            'excerpt' => $trace->toExcerpt(),
            'target' => 'taint',
            'rule_type' => 'taint',
            'trace' => $trace->toArray(),
        ]);
    }
}
