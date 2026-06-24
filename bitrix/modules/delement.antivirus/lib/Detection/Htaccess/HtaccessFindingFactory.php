<?php

namespace Delement\Antivirus\Detection\Htaccess;

use Delement\Antivirus\Detection\Finding;

class HtaccessFindingFactory
{
    public function create(HtaccessRule $rule, string $line, int $lineNumber, string $context = ''): Finding
    {
        $excerpt = trim($line);

        if ($context !== '') {
            $excerpt .= ' | ' . $context;
        }

        return new Finding([
            'signature_id' => $rule->getSignatureId(),
            'name' => $rule->getName(),
            'category' => 'htaccess',
            'severity' => $rule->getSeverity(),
            'score' => $rule->getScore(),
            'offset' => $lineNumber > 0 ? $lineNumber : null,
            'excerpt' => $excerpt,
            'target' => 'htaccess',
            'rule_type' => 'htaccess',
        ]);
    }
}
