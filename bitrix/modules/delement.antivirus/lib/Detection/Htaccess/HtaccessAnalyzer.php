<?php

namespace Delement\Antivirus\Detection\Htaccess;

class HtaccessAnalyzer
{
    private const STATIC_EXTENSIONS = [
        '.jpg' => true,
        '.jpeg' => true,
        '.png' => true,
        '.gif' => true,
        '.txt' => true,
        '.ico' => true,
        '.svg' => true,
        '.css' => true,
        '.js' => true,
        '.webp' => true,
        '.pdf' => true,
        '.zip' => true,
    ];

    private $factory;

    public function __construct(HtaccessFindingFactory $factory = null)
    {
        $this->factory = $factory ?: new HtaccessFindingFactory();
    }

    public function analyze(string $content, string $filePath): array
    {
        if ($content === '') {
            return [];
        }

        $findings = [];
        $lines = preg_split('/\r\n|\r|\n/', $content);
        $recentRewriteContext = [];
        $normalizedPath = $this->normalizePath($filePath);

        foreach ($lines as $index => $line) {
            $lineNumber = $index + 1;
            $trimmed = trim((string)$line);

            if ($trimmed === '' || strpos($trimmed, '#') === 0) {
                continue;
            }

            $this->detectPhpHandler($findings, $trimmed, $lineNumber);
            $this->detectAutoPrependAppend($findings, $trimmed, $lineNumber);
            $this->detectEmbeddedCode($findings, $trimmed, $lineNumber);
            $this->detectForeignCmsMarker($findings, $trimmed, $lineNumber);
            $this->detectAccessBypass($findings, $trimmed, $lineNumber, $normalizedPath);

            if (preg_match('/^\s*RewriteCond\b/i', $trimmed) === 1) {
                $recentRewriteContext[] = $trimmed;

                if (count($recentRewriteContext) > 4) {
                    array_shift($recentRewriteContext);
                }

                continue;
            }

            if (preg_match('/^\s*RewriteRule\b/i', $trimmed) === 1) {
                $this->detectSuspiciousRewrite($findings, $trimmed, $lineNumber, $recentRewriteContext);
                $recentRewriteContext = [];
                continue;
            }

            if (stripos($trimmed, '<FilesMatch') === false && stripos($trimmed, '<Files') === false) {
                $recentRewriteContext = [];
            }
        }

        return $findings;
    }

    private function detectPhpHandler(array &$findings, string $line, int $lineNumber): void
    {
        if (preg_match('/^\s*(AddHandler|AddType)\s+\S*x-httpd-php\S*(.*)$/i', $line, $matches) === 1) {
            $extensions = $this->extractExtensions((string)$matches[2]);

            foreach ($extensions as $extension) {
                if (isset(self::STATIC_EXTENSIONS[$extension])) {
                    $findings[] = $this->factory->create(HtaccessRule::phpHandlerForStaticExt(), $line, $lineNumber, 'extension: ' . $extension);
                    return;
                }
            }
        }

        if (preg_match('/^\s*SetHandler\s+\S*x-httpd-php\S*/i', $line) === 1) {
            $findings[] = $this->factory->create(HtaccessRule::phpHandlerForStaticExt(), $line, $lineNumber);
        }
    }

    private function detectAutoPrependAppend(array &$findings, string $line, int $lineNumber): void
    {
        if (preg_match('/^\s*php_(value|admin_value)\s+auto_(prepend|append)_file\b/i', $line) === 1) {
            $findings[] = $this->factory->create(HtaccessRule::autoPrependAppend(), $line, $lineNumber);
        }
    }

    private function detectEmbeddedCode(array &$findings, string $line, int $lineNumber): void
    {
        if (preg_match('/<\?(php)?|<script\b|eval\s*\(|base64_decode\s*\(/i', $line) === 1) {
            $findings[] = $this->factory->create(HtaccessRule::embeddedCode(), $line, $lineNumber);
        }
    }

    private function detectSuspiciousRewrite(array &$findings, string $line, int $lineNumber, array $context): void
    {
        $haystack = strtolower($line . "\n" . implode("\n", $context));
        $hasSensitiveCondition = preg_match('/%\{(HTTP_USER_AGENT|REMOTE_ADDR)\}/i', $haystack) === 1;
        $hasSuspiciousTarget = preg_match('/\b(cache|shell|tmp|wp-[a-z0-9_-]+|base64|eval)\b|index\.php\?[^ \t]*/i', $haystack) === 1;

        if (!$hasSensitiveCondition && !$hasSuspiciousTarget) {
            return;
        }

        $findings[] = $this->factory->create(
            HtaccessRule::suspiciousRewrite(),
            $line,
            $lineNumber,
            !empty($context) ? 'context: ' . implode(' ; ', $context) : ''
        );
    }

    private function detectForeignCmsMarker(array &$findings, string $line, int $lineNumber): void
    {
        if (preg_match('/\b(wp-config\.php|wp-login\.php|wp-admin|wp-content|wp-includes)\b/i', $line) === 1) {
            $severityRule = HtaccessRule::foreignCmsMarker();

            if (preg_match('/wp-config\.php|wp-login\.php|wp-admin/i', $line) === 1) {
                $severityRule = new HtaccessRule(
                    $severityRule->getSignatureId(),
                    $severityRule->getName(),
                    'high',
                    6
                );
            }

            $findings[] = $this->factory->create($severityRule, $line, $lineNumber);
        }
    }

    private function detectAccessBypass(array &$findings, string $line, int $lineNumber, string $normalizedPath): void
    {
        if (!$this->isSensitivePath($normalizedPath)) {
            return;
        }

        if (preg_match('/^\s*(Order\s+allow,deny|Allow\s+from\s+all|Require\s+all\s+granted|Satisfy\s+Any)\b/i', $line) !== 1) {
            return;
        }

        $findings[] = $this->factory->create(HtaccessRule::accessBypass(), $line, $lineNumber, 'path: ' . $normalizedPath);
    }

    private function extractExtensions(string $line): array
    {
        $extensions = [];

        if (preg_match_all('/\.[a-z0-9_+-]+/i', $line, $matches) !== 1) {
            return [];
        }

        foreach ($matches[0] as $extension) {
            $extensions[] = strtolower((string)$extension);
        }

        return $extensions;
    }

    private function isSensitivePath(string $path): bool
    {
        return strpos($path, '/upload/') !== false
            || strpos($path, '/bitrix/modules/') !== false
            || strpos($path, '/bitrix/php_interface/') !== false;
    }

    private function normalizePath(string $path): string
    {
        return str_replace('\\', '/', strtolower($path));
    }
}
