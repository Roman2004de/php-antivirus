<?php

namespace Delement\Antivirus\Detection\Entropy;

use Delement\Antivirus\Detection\Finding;
use Delement\Antivirus\Detection\Severity;

class EntropyFindingFactory
{
    public function highEncodedPayload(
        string $filePath,
        int $offset,
        string $excerpt,
        float $entropy,
        int $length,
        bool $hasDangerousContext
    ): Finding {
        return new Finding([
            'signature_id' => 'entropy_high_encoded_payload',
            'name' => 'High entropy encoded payload',
            'category' => 'entropy',
            'severity' => $hasDangerousContext ? Severity::HIGH : Severity::MEDIUM,
            'confidence' => $hasDangerousContext ? 'medium' : 'low',
            'score' => $hasDangerousContext ? 7 : 5,
            'offset' => $offset,
            'excerpt' => $excerpt,
            'target' => 'content',
            'rule_type' => 'entropy',
            'file' => $filePath,
            'type' => 'encoded_payload',
            'source' => $hasDangerousContext ? 'high_entropy_with_dangerous_marker' : 'high_entropy_string',
            'entropy' => round($entropy, 4),
            'length' => $length,
            'tags' => [
                'engine:entropy',
                'risk:entropy',
                'risk:encoded_payload',
            ],
        ]);
    }
}
