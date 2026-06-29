<?php

namespace Delement\Antivirus\Detection\Url;

use Delement\Antivirus\Detection\Severity;

class SuspiciousDomainList
{
    private $itemsByDomain = [];

    public static function fromFile(string $path): self
    {
        $list = new self();
        $path = trim($path);

        if ($path === '' || !is_file($path) || !is_readable($path)) {
            return $list;
        }

        $json = @file_get_contents($path);

        if ($json === false || trim($json) === '') {
            return $list;
        }

        $data = json_decode($json, true);

        if (!is_array($data) || !isset($data['items']) || !is_array($data['items'])) {
            return $list;
        }

        foreach ($data['items'] as $item) {
            if (!is_array($item)) {
                continue;
            }

            $domain = self::normalizeDomain((string)($item['domain'] ?? ''));

            if ($domain === '') {
                continue;
            }

            $severity = self::normalizeSeverity((string)($item['severity'] ?? Severity::HIGH));
            $tags = isset($item['tags']) && is_array($item['tags']) ? array_values($item['tags']) : [];
            $list->itemsByDomain[$domain] = [
                'domain' => $domain,
                'severity' => $severity,
                'tags' => $tags,
            ];
        }

        return $list;
    }

    public function match(string $domain): ?array
    {
        $domain = self::normalizeDomain($domain);

        if ($domain === '') {
            return null;
        }

        if (isset($this->itemsByDomain[$domain])) {
            return $this->itemsByDomain[$domain];
        }

        foreach ($this->itemsByDomain as $knownDomain => $item) {
            if (substr($domain, -strlen('.' . $knownDomain)) === '.' . $knownDomain) {
                return $item;
            }
        }

        return null;
    }

    private static function normalizeDomain(string $domain): string
    {
        $domain = strtolower(trim($domain));
        $domain = preg_replace('/^https?:\/\//i', '', $domain);
        $domain = preg_replace('/[\/:].*$/', '', (string)$domain);
        $domain = trim((string)$domain, ". \t\r\n");

        return $domain;
    }

    private static function normalizeSeverity(string $severity): string
    {
        $allowed = [
            Severity::INFO => true,
            Severity::LOW => true,
            Severity::MEDIUM => true,
            Severity::HIGH => true,
            Severity::CRITICAL => true,
        ];

        $severity = strtolower(trim($severity));

        return isset($allowed[$severity]) ? $severity : Severity::HIGH;
    }
}
