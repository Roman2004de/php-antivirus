<?php

namespace Delement\Antivirus\Detection\Hash\Import;

class PanelicaHashNormalizer
{
    private const DEFAULT_NAME = 'Panelica known PHP malware';
    private const DEFAULT_FAMILY = 'unknown';
    private const DEFAULT_CATEGORY = 'webshell';
    private const DEFAULT_TAGS = [
        'known_malware',
        'panelica',
        'php_malware',
    ];

    private $seen = [];
    private $skippedInvalid = 0;
    private $skippedDuplicates = 0;

    public function normalizeJsonData(array $data, string $sourceRef): array
    {
        $rows = $this->extractRows($data);

        return $this->normalizeRows($rows, $sourceRef);
    }

    public function normalizeSha256Text(string $content, string $sourceRef): array
    {
        $rows = [];
        $lines = preg_split('/\r\n|\r|\n/', $content);

        foreach ($lines as $line) {
            $line = trim((string)$line);

            if ($line === '' || strpos($line, '#') === 0) {
                continue;
            }

            $rows[] = $line;
        }

        return $this->normalizeRows($rows, $sourceRef);
    }

    public function getSkippedInvalid(): int
    {
        return $this->skippedInvalid;
    }

    public function getSkippedDuplicates(): int
    {
        return $this->skippedDuplicates;
    }

    private function normalizeRows(array $rows, string $sourceRef): array
    {
        $items = [];

        foreach ($rows as $row) {
            $item = $this->normalizeRow($row, $sourceRef);

            if ($item === null) {
                continue;
            }

            $items[] = $item;
        }

        usort($items, static function (array $left, array $right) {
            return strcmp($left['hash'], $right['hash']);
        });

        return $items;
    }

    private function extractRows(array $data): array
    {
        if (isset($data['items']) && is_array($data['items'])) {
            return $data['items'];
        }

        if (isset($data['hashes']) && is_array($data['hashes'])) {
            return $data['hashes'];
        }

        if (isset($data['hash']) || isset($data['sha256'])) {
            return [$data];
        }

        return $data;
    }

    private function normalizeRow($row, string $sourceRef): ?array
    {
        $raw = is_array($row) ? $row : ['hash' => $row];
        $hash = strtolower(trim((string)($raw['hash'] ?? $raw['sha256'] ?? '')));

        if (preg_match('/^[a-f0-9]{64}$/', $hash) !== 1) {
            $this->skippedInvalid++;
            return null;
        }

        if (isset($this->seen[$hash])) {
            $this->skippedDuplicates++;
            return null;
        }

        $this->seen[$hash] = true;

        $category = $this->stringOrDefault($raw['category'] ?? '', self::DEFAULT_CATEGORY);
        $tags = $this->normalizeTags(array_merge(
            self::DEFAULT_TAGS,
            $this->tagsFromValue($raw['tags'] ?? []),
            $this->categoryTags($category)
        ));

        return [
            'hash' => $hash,
            'name' => $this->stringOrDefault($raw['name'] ?? '', self::DEFAULT_NAME),
            'family' => $this->stringOrDefault($raw['family'] ?? '', self::DEFAULT_FAMILY),
            'category' => $category,
            'description' => trim((string)($raw['description'] ?? '')),
            'severity' => $this->normalizeSeverity((string)($raw['severity'] ?? '')),
            'confidence' => 'high',
            'tags' => $tags,
            'source' => 'panelica',
            'source_ref' => $sourceRef,
        ];
    }

    private function normalizeSeverity(string $severity): string
    {
        $severity = strtolower(trim($severity));

        if ($severity === 'critical' || $severity === 'high') {
            return 'critical';
        }

        if ($severity === 'medium') {
            return 'high';
        }

        return 'critical';
    }

    private function stringOrDefault($value, string $default): string
    {
        $value = trim((string)$value);

        return $value !== '' ? $value : $default;
    }

    private function tagsFromValue($value): array
    {
        if (is_array($value)) {
            return $value;
        }

        $value = trim((string)$value);

        if ($value === '') {
            return [];
        }

        return preg_split('/[,;\s]+/', $value) ?: [];
    }

    private function categoryTags(string $category): array
    {
        $category = strtolower(trim($category));
        $known = [
            'webshell' => true,
            'backdoor' => true,
            'cryptominer' => true,
            'mailer' => true,
            'phishing' => true,
        ];

        return isset($known[$category]) ? [$category] : [];
    }

    private function normalizeTags(array $tags): array
    {
        $result = [];
        $seen = [];

        foreach ($tags as $tag) {
            $tag = strtolower(trim((string)$tag));
            $tag = preg_replace('/[^a-z0-9:_-]+/', '_', $tag);
            $tag = trim((string)$tag, '_');

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
