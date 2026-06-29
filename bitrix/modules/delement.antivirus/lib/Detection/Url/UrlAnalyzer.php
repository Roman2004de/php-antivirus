<?php

namespace Delement\Antivirus\Detection\Url;

use Delement\Antivirus\Config\ScanConfig;

class UrlAnalyzer
{
    private $extractor;
    private $factory;
    private $domainLists = [];

    public function __construct(UrlExtractor $extractor = null, UrlFindingFactory $factory = null)
    {
        $this->extractor = $extractor ?: new UrlExtractor();
        $this->factory = $factory ?: new UrlFindingFactory();
    }

    public function analyze(string $content, string $filePath, ScanConfig $config): array
    {
        $findings = [];
        $seen = [];
        $domainList = $this->domainList($config->getSuspiciousDomainsPath());

        foreach ($this->extractor->extract($content, $filePath) as $url) {
            $this->addFinding($findings, $seen, $this->factory->externalUrl($url));

            $domainMatch = $domainList->match((string)($url['domain'] ?? ''));

            if ($domainMatch !== null) {
                $this->addFinding($findings, $seen, $this->factory->suspiciousDomainMatch($url, $domainMatch));
            }

            if ($this->isIframeUrl($url)) {
                $this->addFinding($findings, $seen, $this->factory->suspiciousIframe($url));
            }

            if ($this->isExternalScriptInjection($url)) {
                $this->addFinding($findings, $seen, $this->factory->externalScriptInjection($url));
            }

            if ($this->isRemotePayloadLoader($url)) {
                $this->addFinding($findings, $seen, $this->factory->remotePayloadLoader($url));
            }

            if ($this->isHtaccessExternalRedirect($url, $filePath)) {
                $this->addFinding($findings, $seen, $this->factory->htaccessExternalRedirect($url));
            }
        }

        return $findings;
    }

    private function domainList(string $path): SuspiciousDomainList
    {
        $key = $path !== '' ? $path : '__empty__';

        if (!isset($this->domainLists[$key])) {
            $this->domainLists[$key] = SuspiciousDomainList::fromFile($path);
        }

        return $this->domainLists[$key];
    }

    private function isIframeUrl(array $url): bool
    {
        $line = (string)($url['line_text'] ?? '');
        $context = (string)($url['context'] ?? '');

        return preg_match('/<iframe\b[^>]*\bsrc\s*=/i', $line) === 1
            || preg_match('/<iframe\b[^>]*\bsrc\s*=/i', $context) === 1;
    }

    private function isExternalScriptInjection(array $url): bool
    {
        $line = (string)($url['line_text'] ?? '');
        $context = (string)($url['context'] ?? '');

        if (preg_match('/<script\b[^>]*\bsrc\s*=/i', $line) === 1 || preg_match('/<script\b[^>]*\bsrc\s*=/i', $context) === 1) {
            return true;
        }

        return stripos($context, 'document.write') !== false && stripos($context, '<script') !== false;
    }

    private function isRemotePayloadLoader(array $url): bool
    {
        $context = (string)($url['context'] ?? '');

        return preg_match('/\b(curl_setopt|CURLOPT_URL|file_get_contents|fopen|readfile|include|include_once|require|require_once|fsockopen|stream_socket_client)\b/i', $context) === 1;
    }

    private function isHtaccessExternalRedirect(array $url, string $filePath): bool
    {
        if (basename($filePath) !== '.htaccess') {
            return false;
        }

        $line = (string)($url['line_text'] ?? '');

        return preg_match('/^\s*(RewriteRule|Redirect|RedirectMatch)\b/i', $line) === 1;
    }

    private function addFinding(array &$findings, array &$seen, $finding): void
    {
        if ($finding === null) {
            return;
        }

        $data = $finding->toArray();
        $key = implode(':', [
            (string)($data['signature_id'] ?? ''),
            (string)($data['url'] ?? ''),
            (string)($data['offset'] ?? ''),
            (string)($data['type'] ?? ''),
        ]);

        if (isset($seen[$key])) {
            return;
        }

        $findings[] = $finding;
        $seen[$key] = true;
    }
}
