<?php

namespace Delement\Antivirus\Storage;

use RuntimeException;

class RuntimeDirectory
{
    private const DIRECTORY_MODE = 0700;
    private const FILE_MODE = 0600;
    private const RUNTIME_PATH_NAME = 'DELEMENT_ANTIVIRUS_RUNTIME_PATH';
    private const ALLOW_WEB_ROOT_NAME = 'DELEMENT_ANTIVIRUS_RUNTIME_ALLOW_WEB_ROOT';

    public static function resolve(string $moduleRoot, string $name): string
    {
        $name = trim($name, '/\\');

        if ($name === '' || !preg_match('/^[a-zA-Z0-9_.-]+$/', $name)) {
            throw new RuntimeException('runtime_directory_name_invalid');
        }

        foreach (self::getCandidates($moduleRoot, $name) as $path) {
            if (self::prepare($path)) {
                self::migrateLegacyData($path, $moduleRoot, $name);
                return $path;
            }
        }

        throw new RuntimeException('runtime_directory_prepare_failed');
    }

    private static function getCandidates(string $moduleRoot, string $name): array
    {
        $candidates = [];
        $documentRoot = isset($_SERVER['DOCUMENT_ROOT']) ? rtrim((string)$_SERVER['DOCUMENT_ROOT'], '/\\') : '';
        $siteKey = self::siteKey($moduleRoot, $documentRoot);
        $configuredRuntimeRoot = self::configuredRuntimeRoot();

        if ($configuredRuntimeRoot !== '') {
            $candidates[] = rtrim($configuredRuntimeRoot, '/\\') . '/' . $name;
        }

        if ($documentRoot !== '') {
            $candidates[] = dirname($documentRoot) . '/.delement.antivirus/' . $siteKey . '/' . $name;
        }

        $candidates[] = rtrim($moduleRoot, '/\\') . '/var/' . $name;

        if (function_exists('sys_get_temp_dir')) {
            $candidates[] = rtrim(sys_get_temp_dir(), '/\\') . '/delement.antivirus/' . $siteKey . '/' . $name;
        }

        if (self::allowWebRootRuntime()) {
            if ($documentRoot !== '') {
                $candidates[] = $documentRoot . '/bitrix/tmp/delement.antivirus/' . $name;
            }

            $candidates[] = rtrim($moduleRoot, '/\\') . '/var/' . $name;
        }

        return self::filterCandidates($candidates, $documentRoot);
    }

    private static function prepare(string $path): bool
    {
        if (!is_dir($path) && !@mkdir($path, self::DIRECTORY_MODE, true) && !is_dir($path)) {
            return false;
        }

        if (!is_writable($path)) {
            return false;
        }

        @chmod($path, self::DIRECTORY_MODE);

        self::protect(dirname($path));
        self::protect($path);

        return true;
    }

    private static function protect(string $path): void
    {
        if (!is_dir($path) || !is_writable($path)) {
            return;
        }

        @chmod($path, self::DIRECTORY_MODE);

        $htaccess = rtrim($path, '/\\') . '/.htaccess';
        $index = rtrim($path, '/\\') . '/index.php';

        if (!is_file($htaccess)) {
            @file_put_contents(
                $htaccess,
                "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n"
            );
            @chmod($htaccess, self::FILE_MODE);
        }

        if (!is_file($index)) {
            @file_put_contents($index, "<?php\nhttp_response_code(403);\n");
            @chmod($index, self::FILE_MODE);
        }

        @chmod($htaccess, self::FILE_MODE);
        @chmod($index, self::FILE_MODE);
    }

    private static function filterCandidates(array $candidates, string $documentRoot): array
    {
        $filtered = [];
        $seen = [];
        $allowWebRootRuntime = self::allowWebRootRuntime();

        foreach ($candidates as $candidate) {
            $candidate = rtrim((string)$candidate, '/\\');

            if ($candidate === '') {
                continue;
            }

            if (!$allowWebRootRuntime && self::isInsideDocumentRoot($candidate, $documentRoot)) {
                continue;
            }

            $key = self::normalizePath($candidate);

            if (!isset($seen[$key])) {
                $filtered[] = $candidate;
                $seen[$key] = true;
            }
        }

        return $filtered;
    }

    private static function configuredRuntimeRoot(): string
    {
        if (defined(self::RUNTIME_PATH_NAME)) {
            return rtrim((string)constant(self::RUNTIME_PATH_NAME), '/\\');
        }

        $value = getenv(self::RUNTIME_PATH_NAME);

        return is_string($value) ? rtrim($value, '/\\') : '';
    }

    private static function allowWebRootRuntime(): bool
    {
        if (defined(self::ALLOW_WEB_ROOT_NAME)) {
            return self::normalizeBool(constant(self::ALLOW_WEB_ROOT_NAME));
        }

        $value = getenv(self::ALLOW_WEB_ROOT_NAME);

        return self::normalizeBool($value);
    }

    private static function normalizeBool($value): bool
    {
        if (is_bool($value)) {
            return $value;
        }

        return in_array(strtolower(trim((string)$value)), ['1', 'y', 'yes', 'true', 'on'], true);
    }

    private static function siteKey(string $moduleRoot, string $documentRoot): string
    {
        $source = $documentRoot !== '' ? $documentRoot : $moduleRoot;

        return substr(hash('sha256', self::normalizePath($source)), 0, 16);
    }

    private static function isInsideDocumentRoot(string $path, string $documentRoot): bool
    {
        if ($documentRoot === '') {
            return false;
        }

        $normalizedPath = self::normalizePath($path);
        $normalizedDocumentRoot = self::normalizePath($documentRoot);

        return $normalizedPath === $normalizedDocumentRoot
            || strpos($normalizedPath, $normalizedDocumentRoot . '/') === 0;
    }

    private static function normalizePath(string $path): string
    {
        return str_replace('\\', '/', strtolower(rtrim($path, '/\\')));
    }

    private static function migrateLegacyData(string $targetPath, string $moduleRoot, string $name): void
    {
        foreach (self::getLegacyCandidates($moduleRoot, $name) as $legacyPath) {
            if (!is_dir($legacyPath) || self::normalizePath($legacyPath) === self::normalizePath($targetPath)) {
                continue;
            }

            self::migrateDirectoryContents($legacyPath, $targetPath);
            self::removeLegacyProtectionFiles($legacyPath);
            @rmdir($legacyPath);
        }
    }

    private static function getLegacyCandidates(string $moduleRoot, string $name): array
    {
        $candidates = [];
        $documentRoot = isset($_SERVER['DOCUMENT_ROOT']) ? rtrim((string)$_SERVER['DOCUMENT_ROOT'], '/\\') : '';

        if ($documentRoot !== '') {
            $candidates[] = $documentRoot . '/bitrix/tmp/delement.antivirus/' . $name;
        }

        $candidates[] = rtrim($moduleRoot, '/\\') . '/var/' . $name;

        return $candidates;
    }

    private static function migrateDirectoryContents(string $sourcePath, string $targetPath): void
    {
        $items = @scandir($sourcePath);

        if ($items === false) {
            return;
        }

        foreach ($items as $item) {
            if ($item === '.' || $item === '..' || $item === '.htaccess' || $item === 'index.php') {
                continue;
            }

            $sourceItem = rtrim($sourcePath, '/\\') . DIRECTORY_SEPARATOR . $item;
            $targetItem = rtrim($targetPath, '/\\') . DIRECTORY_SEPARATOR . $item;

            if (is_dir($sourceItem)) {
                if (self::prepare($targetItem)) {
                    self::migrateDirectoryContents($sourceItem, $targetItem);
                    self::removeLegacyProtectionFiles($sourceItem);
                    @rmdir($sourceItem);
                }

                continue;
            }

            if (!is_file($sourceItem)) {
                continue;
            }

            if (!is_file($targetItem)) {
                if (!@copy($sourceItem, $targetItem)) {
                    continue;
                }

                @chmod($targetItem, self::FILE_MODE);
            }

            @unlink($sourceItem);
        }
    }

    private static function removeLegacyProtectionFiles(string $path): void
    {
        @unlink(rtrim($path, '/\\') . DIRECTORY_SEPARATOR . '.htaccess');
        @unlink(rtrim($path, '/\\') . DIRECTORY_SEPARATOR . 'index.php');
    }
}
