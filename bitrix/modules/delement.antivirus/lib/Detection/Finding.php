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
    private $file;
    private $line;
    private $type;
    private $source;
    private $fingerprint;
    private $confidence;
    private $entropy;
    private $length;
    private $url;
    private $domain;
    private $tags = [];

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
        $this->file = isset($data['file']) ? (string)$data['file'] : '';
        $this->line = isset($data['line']) ? (int)$data['line'] : null;
        $this->type = isset($data['type']) ? (string)$data['type'] : '';
        $this->source = isset($data['source']) ? (string)$data['source'] : '';
        $this->fingerprint = isset($data['fingerprint']) ? (string)$data['fingerprint'] : '';
        $this->confidence = isset($data['confidence']) ? (string)$data['confidence'] : '';
        $this->entropy = isset($data['entropy']) && $data['entropy'] !== null ? (float)$data['entropy'] : null;
        $this->length = isset($data['length']) && $data['length'] !== null ? (int)$data['length'] : null;
        $this->url = isset($data['url']) ? (string)$data['url'] : '';
        $this->domain = isset($data['domain']) ? (string)$data['domain'] : '';
        $this->tags = isset($data['tags']) && is_array($data['tags']) ? self::normalizeTags($data['tags']) : [];
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

    public function getOffset()
    {
        return $this->offset;
    }

    public function getExcerpt(): string
    {
        return $this->excerpt;
    }

    public function getTarget(): string
    {
        return $this->target;
    }

    public function getRuleType(): string
    {
        return $this->ruleType;
    }

    public function getCategory(): string
    {
        return $this->category;
    }

    public function getTags(): array
    {
        return $this->tags;
    }

    public function getFingerprint(): string
    {
        return $this->fingerprint;
    }

    public function withFingerprint(string $fingerprint): self
    {
        $copy = clone $this;
        $copy->fingerprint = $fingerprint;

        return $copy;
    }

    public function withTags(array $tags): self
    {
        $copy = clone $this;
        $copy->tags = self::normalizeTags($tags);

        return $copy;
    }

    public function addTag(string $tag): self
    {
        return $this->withTags(array_merge($this->tags, [$tag]));
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
            'fingerprint' => $this->fingerprint,
            'tags' => $this->tags,
        ];

        if (!empty($this->trace)) {
            $result['trace'] = $this->trace;
        }

        if ($this->file !== '') {
            $result['file'] = $this->file;
        }

        if ($this->line !== null) {
            $result['line'] = $this->line;
        }

        if ($this->type !== '') {
            $result['type'] = $this->type;
        }

        if ($this->source !== '') {
            $result['source'] = $this->source;
        }

        if ($this->confidence !== '') {
            $result['confidence'] = $this->confidence;
        }

        if ($this->entropy !== null) {
            $result['entropy'] = $this->entropy;
        }

        if ($this->length !== null) {
            $result['length'] = $this->length;
        }

        if ($this->url !== '') {
            $result['url'] = $this->url;
        }

        if ($this->domain !== '') {
            $result['domain'] = $this->domain;
        }

        return $result;
    }

    private static function normalizeTags(array $tags): array
    {
        $result = [];
        $seen = [];

        foreach ($tags as $tag) {
            $tag = strtolower(trim((string)$tag));

            if ($tag === '' || isset($seen[$tag])) {
                continue;
            }

            $result[] = $tag;
            $seen[$tag] = true;
        }

        sort($result, SORT_STRING);

        return $result;
    }
}
