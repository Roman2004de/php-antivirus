<?php

namespace Delement\Antivirus\Detection;

class Finding
{
    private $signatureId;
    private $name;
    private $category;
    private $severity;
    private $score;
    private $offset;
    private $excerpt;
    private $target;
    private $ruleType;
    private $trace;

    public function __construct(array $data)
    {
        $this->signatureId = isset($data['signature_id']) ? (string)$data['signature_id'] : '';
        $this->name = isset($data['name']) ? (string)$data['name'] : $this->signatureId;
        $this->category = isset($data['category']) ? (string)$data['category'] : 'generic';
        $this->severity = isset($data['severity']) ? (string)$data['severity'] : Severity::LOW;
        $this->score = isset($data['score']) ? (int)$data['score'] : 1;
        $this->offset = isset($data['offset']) ? (int)$data['offset'] : null;
        $this->excerpt = isset($data['excerpt']) ? (string)$data['excerpt'] : '';
        $this->target = isset($data['target']) ? (string)$data['target'] : 'content';
        $this->ruleType = isset($data['rule_type']) ? (string)$data['rule_type'] : 'regex';
        $this->trace = isset($data['trace']) && is_array($data['trace']) ? $data['trace'] : [];
    }

    public function getSignatureId(): string
    {
        return $this->signatureId;
    }

    public function getSeverity(): string
    {
        return $this->severity;
    }

    public function getScore(): int
    {
        return $this->score;
    }

    public function toArray(): array
    {
        $result = [
            'signature_id' => $this->signatureId,
            'name' => $this->name,
            'category' => $this->category,
            'severity' => $this->severity,
            'score' => $this->score,
            'offset' => $this->offset,
            'excerpt' => $this->excerpt,
            'target' => $this->target,
            'rule_type' => $this->ruleType,
        ];

        if (!empty($this->trace)) {
            $result['trace'] = $this->trace;
        }

        return $result;
    }
}
