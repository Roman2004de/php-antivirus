<?php

namespace Delement\Antivirus\Detection\Hash;

class HashPrefixIndex
{
    private $prefixLength = 8;
    private $prefixes = [];
    private $active = false;
    private $warnings = [];

    public static function fromFile(string $path): self
    {
        $index = new self();
        $path = trim($path);

        if ($path === '') {
            return $index;
        }

        if (!is_file($path)) {
            return $index;
        }

        if (!is_readable($path)) {
            $index->warnings[] = 'malware_hash_prefixes_not_readable:' . $path;
            return $index;
        }

        $json = @file_get_contents($path);

        if ($json === false || trim($json) === '') {
            $index->warnings[] = 'malware_hash_prefixes_empty_or_unreadable:' . $path;
            return $index;
        }

        $data = json_decode($json, true);

        if (!is_array($data) || !isset($data['prefixes']) || !is_array($data['prefixes'])) {
            $index->warnings[] = 'malware_hash_prefixes_invalid_json:' . $path;
            return $index;
        }

        $algorithm = strtolower((string)($data['algorithm'] ?? 'sha256'));

        if ($algorithm !== 'sha256') {
            $index->warnings[] = 'malware_hash_prefixes_unsupported_algorithm:' . $algorithm;
            return $index;
        }

        $prefixLength = isset($data['prefix_length']) ? (int)$data['prefix_length'] : 8;
        $prefixLength = max(8, min(12, $prefixLength));
        $prefixes = [];

        foreach ($data['prefixes'] as $prefix) {
            $prefix = strtolower(trim((string)$prefix));

            if (preg_match('/^[a-f0-9]{' . $prefixLength . '}$/', $prefix) !== 1) {
                continue;
            }

            $prefixes[$prefix] = true;
        }

        $index->prefixLength = $prefixLength;
        $index->prefixes = $prefixes;
        $index->active = !empty($prefixes);

        return $index;
    }

    public function mayContain(string $hash): bool
    {
        if (!$this->active) {
            return true;
        }

        $prefix = substr(strtolower($hash), 0, $this->prefixLength);

        return isset($this->prefixes[$prefix]);
    }

    public function getWarnings(): array
    {
        return $this->warnings;
    }

    public function count(): int
    {
        return count($this->prefixes);
    }

    public function getPrefixLength(): int
    {
        return $this->prefixLength;
    }
}
