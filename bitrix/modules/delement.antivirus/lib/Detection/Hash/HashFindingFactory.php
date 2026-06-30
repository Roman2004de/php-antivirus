<?php

namespace Delement\Antivirus\Detection\Hash;

use Delement\Antivirus\Detection\Finding;
use Delement\Antivirus\Detection\Severity;

class HashFindingFactory
{
    public function knownMalware(string $filePath, string $hash, array $item): Finding
    {
        return new Finding([
            'signature_id' => 'known_malware_hash_match',
            'name' => (string)($item['name'] ?? 'Known malware hash match'),
            'category' => 'hash_db',
            'severity' => Severity::CRITICAL,
            'score' => 100,
            'offset' => null,
            'excerpt' => substr($hash, 0, 16) . '...',
            'target' => 'file_hash',
            'rule_type' => 'hash',
            'file' => $filePath,
            'type' => 'known_malware_hash',
            'source' => (string)($item['source'] ?? 'malware_hashes'),
            'confidence' => (string)($item['confidence'] ?? 'high'),
            'hash' => $hash,
            'hash_algorithm' => 'sha256',
            'recommendation' => 'quarantine',
            'trace' => [
                'source' => (string)($item['source'] ?? 'malware_hashes'),
                'hash' => $hash,
                'algorithm' => 'sha256',
                'family' => (string)($item['family'] ?? ''),
                'category' => (string)($item['category'] ?? ''),
                'source_ref' => (string)($item['source_ref'] ?? ''),
                'matched_name' => (string)($item['name'] ?? ''),
                'matched_severity' => (string)($item['severity'] ?? Severity::CRITICAL),
                'matched_tags' => isset($item['tags']) && is_array($item['tags']) ? array_values($item['tags']) : [],
                'recommendation' => 'quarantine',
            ],
            'tags' => array_merge([
                'engine:hash_db',
                'risk:known_malware_hash',
            ], $this->domainTags($item['tags'] ?? [])),
        ]);
    }

    public function runtimeWarning(string $filePath, string $message): Finding
    {
        return new Finding([
            'signature_id' => 'hash_db_runtime_warning',
            'name' => 'Hash database runtime warning',
            'category' => 'hash_db',
            'severity' => Severity::INFO,
            'score' => 0,
            'offset' => null,
            'excerpt' => $message,
            'target' => 'hash_db',
            'rule_type' => 'hash_db',
            'file' => $filePath,
            'type' => 'runtime_warning',
            'source' => 'hash_database',
            'trace' => [
                'warning' => $message,
            ],
            'tags' => [
                'engine:hash_db',
            ],
        ]);
    }

    private function domainTags($tags): array
    {
        if (!is_array($tags)) {
            return [];
        }

        $result = [];

        foreach ($tags as $tag) {
            $tag = strtolower(trim((string)$tag));

            if ($tag !== '') {
                $result[] = $tag;
            }
        }

        return $result;
    }
}
