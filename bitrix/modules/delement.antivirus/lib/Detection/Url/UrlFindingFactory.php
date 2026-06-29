<?php

namespace Delement\Antivirus\Detection\Url;

use Delement\Antivirus\Detection\Finding;
use Delement\Antivirus\Detection\Severity;

class UrlFindingFactory
{
    public function externalUrl(array $url): Finding
    {
        return $this->create('external_url_detected', Severity::INFO, 0, $url, 'external_url', [
            'engine:url',
            'risk:external_url',
        ]);
    }

    public function suspiciousIframe(array $url): Finding
    {
        return $this->create('suspicious_iframe_url', Severity::HIGH, 5, $url, 'iframe_url', [
            'engine:url',
            'risk:external_url',
            'risk:remote_loader',
        ]);
    }

    public function remotePayloadLoader(array $url): Finding
    {
        return $this->create('remote_payload_loader', Severity::HIGH, 6, $url, 'remote_payload_loader', [
            'engine:url',
            'risk:external_url',
            'risk:remote_loader',
        ]);
    }

    public function externalScriptInjection(array $url): Finding
    {
        return $this->create('external_script_injection', Severity::HIGH, 6, $url, 'external_script_injection', [
            'engine:url',
            'risk:external_url',
            'risk:remote_loader',
        ]);
    }

    public function htaccessExternalRedirect(array $url): Finding
    {
        return $this->create('htaccess_external_redirect', Severity::HIGH, 5, $url, 'htaccess_external_redirect', [
            'engine:url',
            'risk:external_url',
        ]);
    }

    public function suspiciousDomainMatch(array $url, array $match): Finding
    {
        $severity = (string)($match['severity'] ?? Severity::HIGH);

        return $this->create(
            'suspicious_domain_match',
            $severity,
            $this->scoreForSeverity($severity),
            $url,
            'suspicious_domain',
            array_merge([
                'engine:url',
                'risk:external_url',
                'risk:remote_loader',
            ], $this->domainTags($match['tags'] ?? [])),
            [
                'matched_domain' => (string)($match['domain'] ?? ''),
                'domain_tags' => isset($match['tags']) && is_array($match['tags']) ? array_values($match['tags']) : [],
            ]
        );
    }

    private function create(string $signatureId, string $severity, int $score, array $url, string $type, array $tags, array $extraTrace = []): Finding
    {
        $trace = array_merge([
            'url' => (string)($url['url'] ?? ''),
            'domain' => (string)($url['domain'] ?? ''),
            'context' => (string)($url['line_text'] ?? ''),
            'line' => (int)($url['line'] ?? 0),
        ], $extraTrace);

        return new Finding([
            'signature_id' => $signatureId,
            'name' => $signatureId,
            'category' => 'url',
            'severity' => $severity,
            'score' => $score,
            'offset' => isset($url['offset']) ? (int)$url['offset'] : null,
            'excerpt' => $this->excerpt((string)($url['context'] ?? ($url['url'] ?? ''))),
            'target' => 'content',
            'rule_type' => 'url',
            'file' => (string)($url['file_path'] ?? ''),
            'line' => isset($url['line']) ? (int)$url['line'] : null,
            'type' => $type,
            'source' => $type,
            'url' => (string)($url['url'] ?? ''),
            'domain' => (string)($url['domain'] ?? ''),
            'trace' => $trace,
            'tags' => $tags,
        ]);
    }

    private function scoreForSeverity(string $severity): int
    {
        if ($severity === Severity::CRITICAL) {
            return 10;
        }

        if ($severity === Severity::HIGH) {
            return 7;
        }

        if ($severity === Severity::MEDIUM) {
            return 4;
        }

        if ($severity === Severity::LOW) {
            return 2;
        }

        return 0;
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
                $result[] = 'domain:' . $tag;
            }
        }

        return $result;
    }

    private function excerpt(string $context): string
    {
        $context = trim((string)preg_replace('/\s+/', ' ', $context));

        if (strlen($context) <= 180) {
            return $context;
        }

        return substr($context, 0, 150) . '...';
    }
}
