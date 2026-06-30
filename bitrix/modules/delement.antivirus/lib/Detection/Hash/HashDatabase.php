<?php

namespace Delement\Antivirus\Detection\Hash;

use Delement\Antivirus\Detection\Severity;

class HashDatabase
{
    private $itemsByHash = [];
    private $warnings = [];
    private $source = [];

    public static function fromFile(string $path): self
    {
        $database = new self();
        $path = trim($path);

        if ($path === '') {
            return $database;
        }

        if (!is_file($path)) {
            return $database;
        }

        if (!is_readable($path)) {
            $database->warnings[] = 'malware_hashes_not_readable:' . $path;
            return $database;
        }

        $json = @file_get_contents($path);

        if ($json === false || trim($json) === '') {
            $database->warnings[] = 'malware_hashes_empty_or_unreadable:' . $path;
            return $database;
        }

        $data = json_decode($json, true);

        if (!is_array($data) || !isset($data['items']) || !is_array($data['items'])) {
            $database->warnings[] = 'malware_hashes_invalid_json:' . $path;
            return $database;
        }

        $algorithm = strtolower((string)($data['algorithm'] ?? 'sha256'));

        if ($algorithm !== 'sha256') {
            $database->warnings[] = 'malware_hashes_unsupported_algorithm:' . $algorithm;
            return $database;
        }

        $database->source = isset($data['source']) && is_array($data['source']) ? $data['source'] : [];

        foreach ($data['items'] as $item) {
            if (!is_array($item)) {
                continue;
            }

            $hash = strtolower(trim((string)($item['hash'] ?? '')));

            if (preg_match('/^[a-f0-9]{64}$/', $hash) !== 1) {
                continue;
            }

            $database->itemsByHash[$hash] = [
                'hash' => $hash,
                'name' => trim((string)($item['name'] ?? 'Known malware')),
                'family' => trim((string)($item['family'] ?? '')),
                'category' => trim((string)($item['category'] ?? '')),
                'description' => trim((string)($item['description'] ?? '')),
                'severity' => self::normalizeSeverity((string)($item['severity'] ?? Severity::CRITICAL)),
                'confidence' => trim((string)($item['confidence'] ?? 'high')),
                'tags' => isset($item['tags']) && is_array($item['tags']) ? array_values($item['tags']) : [],
                'source' => trim((string)($item['source'] ?? ($database->source['name'] ?? 'malware_hashes'))),
                'source_ref' => trim((string)($item['source_ref'] ?? '')),
            ];
        }

        return $database;
    }

    public function find(string $hash): ?array
    {
        $hash = strtolower(trim($hash));

        return $this->itemsByHash[$hash] ?? null;
    }

    public function getWarnings(): array
    {
        return $this->warnings;
    }

    public function count(): int
    {
        return count($this->itemsByHash);
    }

    public function getSource(): array
    {
        return $this->source;
    }

    private static function normalizeSeverity(string $severity): string
    {
        $severity = strtolower(trim($severity));
        $allowed = [
            Severity::LOW => true,
            Severity::MEDIUM => true,
            Severity::HIGH => true,
            Severity::CRITICAL => true,
        ];

        return isset($allowed[$severity]) ? $severity : Severity::CRITICAL;
    }
}
