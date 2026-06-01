<?php

namespace Delement\Antivirus\Storage;

use RuntimeException;

class RuntimeDirectory
{
    public static function resolve(string $moduleRoot, string $name): string
    {
        $name = trim($name, '/\\');

        if ($name === '' || !preg_match('/^[a-zA-Z0-9_.-]+$/', $name)) {
            throw new RuntimeException('Invalid runtime directory name');
        }

        foreach (self::getCandidates($moduleRoot, $name) as $path) {
            if (self::prepare($path)) {
                return $path;
            }
        }

        throw new RuntimeException('Cannot prepare writable runtime directory for ' . $name);
    }

    private static function getCandidates(string $moduleRoot, string $name): array
    {
        $candidates = [];
        $documentRoot = isset($_SERVER['DOCUMENT_ROOT']) ? rtrim((string)$_SERVER['DOCUMENT_ROOT'], '/\\') : '';

        if ($documentRoot !== '') {
            $candidates[] = $documentRoot . '/bitrix/tmp/delement.antivirus/' . $name;
        }

        $candidates[] = rtrim($moduleRoot, '/\\') . '/var/' . $name;

        if (function_exists('sys_get_temp_dir')) {
            $candidates[] = rtrim(sys_get_temp_dir(), '/\\') . '/delement.antivirus/' . $name;
        }

        return $candidates;
    }

    private static function prepare(string $path): bool
    {
        if (!is_dir($path) && !@mkdir($path, 0755, true) && !is_dir($path)) {
            return false;
        }

        if (!is_writable($path)) {
            return false;
        }

        self::protect(dirname($path));
        self::protect($path);

        return true;
    }

    private static function protect(string $path): void
    {
        if (!is_dir($path) || !is_writable($path)) {
            return;
        }

        $htaccess = rtrim($path, '/\\') . '/.htaccess';
        $index = rtrim($path, '/\\') . '/index.php';

        if (!is_file($htaccess)) {
            @file_put_contents(
                $htaccess,
                "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n"
            );
        }

        if (!is_file($index)) {
            @file_put_contents($index, "<?php\nhttp_response_code(403);\n");
        }
    }
}
