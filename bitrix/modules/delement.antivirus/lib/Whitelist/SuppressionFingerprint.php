<?php

namespace Delement\Antivirus\Whitelist;

class SuppressionFingerprint
{
    private const EXCERPT_LIMIT = 512;

    public static function forFinding(string $filePath, array $finding, string $documentRoot = ''): string
    {
        return hash('sha256', implode("\n", [
            self::normalizeRelativePath($filePath, $documentRoot),
            self::normalizeSignatureId(isset($finding['signature_id']) ? (string)$finding['signature_id'] : ''),
            self::normalizeTarget(isset($finding['target']) ? (string)$finding['target'] : ''),
            self::excerptHash(isset($finding['excerpt']) ? (string)$finding['excerpt'] : ''),
        ]));
    }

    public static function excerptHash(string $excerpt): string
    {
        $excerpt = trim((string)preg_replace('/\s+/', ' ', $excerpt));
        $excerpt = substr($excerpt, 0, self::EXCERPT_LIMIT);

        return hash('sha256', $excerpt);
    }

    public static function normalizeRelativePath(string $filePath, string $documentRoot = ''): string
    {
        $filePath = self::normalizePath($filePath);
        $documentRoot = self::normalizePath($documentRoot);

        if ($documentRoot !== '') {
            if ($filePath === $documentRoot) {
                return '/';
            }

            if (strpos($filePath, $documentRoot . '/') === 0) {
                return '/' . ltrim(substr($filePath, strlen($documentRoot)), '/');
            }
        }

        return $filePath;
    }

    private static function normalizePath(string $path): string
    {
        $path = str_replace('\\', '/', trim($path));
        $path = preg_replace('#/+#', '/', $path);

        return strtolower(rtrim((string)$path, '/'));
    }

    private static function normalizeSignatureId(string $signatureId): string
    {
        return strtolower(trim($signatureId));
    }

    private static function normalizeTarget(string $target): string
    {
        $target = strtolower(trim($target));

        return $target !== '' ? $target : 'content';
    }
}
