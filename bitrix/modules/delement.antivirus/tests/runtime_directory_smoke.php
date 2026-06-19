<?php

use Delement\Antivirus\Storage\RuntimeDirectory;

require_once __DIR__ . '/../lib/Storage/RuntimeDirectory.php';

function delement_antivirus_runtime_remove_tree(string $path): void
{
    if (!is_dir($path)) {
        return;
    }

    $items = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );

    foreach ($items as $item) {
        if ($item->isDir()) {
            @rmdir($item->getPathname());
        } else {
            @unlink($item->getPathname());
        }
    }

    @rmdir($path);
}

function delement_antivirus_runtime_normalize_path(string $path): string
{
    return str_replace('\\', '/', strtolower(rtrim($path, '/\\')));
}

function delement_antivirus_runtime_path_inside(string $path, string $basePath): bool
{
    $path = delement_antivirus_runtime_normalize_path($path);
    $basePath = delement_antivirus_runtime_normalize_path($basePath);

    return $path === $basePath || strpos($path, $basePath . '/') === 0;
}

function delement_antivirus_runtime_fail(string $message, array $context = []): void
{
    fwrite(STDERR, $message . PHP_EOL);

    if (!empty($context)) {
        fwrite(STDERR, json_encode($context, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    }

    exit(1);
}

$oldDocumentRoot = $_SERVER['DOCUMENT_ROOT'] ?? null;
$oldRuntimePath = getenv('DELEMENT_ANTIVIRUS_RUNTIME_PATH');
$oldAllowWebRoot = getenv('DELEMENT_ANTIVIRUS_RUNTIME_ALLOW_WEB_ROOT');

$root = rtrim(sys_get_temp_dir(), '/\\') . DIRECTORY_SEPARATOR . 'delement_antivirus_runtime_smoke_' . getmypid();
$documentRoot = $root . DIRECTORY_SEPARATOR . 'site' . DIRECTORY_SEPARATOR . 'public';
$moduleRoot = $documentRoot . DIRECTORY_SEPARATOR . 'bitrix' . DIRECTORY_SEPARATOR . 'modules' . DIRECTORY_SEPARATOR . 'delement.antivirus';
$legacyWhitelistPath = $documentRoot . DIRECTORY_SEPARATOR . 'bitrix' . DIRECTORY_SEPARATOR . 'tmp' . DIRECTORY_SEPARATOR . 'delement.antivirus' . DIRECTORY_SEPARATOR . 'whitelist';
$legacyRulesPath = $legacyWhitelistPath . DIRECTORY_SEPARATOR . 'rules.json';
$configuredWebRootPath = $documentRoot . DIRECTORY_SEPARATOR . 'runtime';

try {
    delement_antivirus_runtime_remove_tree($root);

    if (!mkdir($moduleRoot, 0777, true) && !is_dir($moduleRoot)) {
        delement_antivirus_runtime_fail('Cannot create module root');
    }

    if (!mkdir($legacyWhitelistPath, 0777, true) && !is_dir($legacyWhitelistPath)) {
        delement_antivirus_runtime_fail('Cannot create legacy runtime directory');
    }

    file_put_contents($legacyRulesPath, '{"rules":[]}');
    file_put_contents($legacyWhitelistPath . DIRECTORY_SEPARATOR . '.htaccess', 'deny');
    file_put_contents($legacyWhitelistPath . DIRECTORY_SEPARATOR . 'index.php', "<?php\n");

    $_SERVER['DOCUMENT_ROOT'] = $documentRoot;
    putenv('DELEMENT_ANTIVIRUS_RUNTIME_PATH');
    putenv('DELEMENT_ANTIVIRUS_RUNTIME_ALLOW_WEB_ROOT');

    $runtimePath = RuntimeDirectory::resolve($moduleRoot, 'whitelist');
    $migratedRulesPath = $runtimePath . DIRECTORY_SEPARATOR . 'rules.json';

    if (delement_antivirus_runtime_path_inside($runtimePath, $documentRoot)) {
        delement_antivirus_runtime_fail('Runtime path is inside DOCUMENT_ROOT', [
            'runtime_path' => $runtimePath,
            'document_root' => $documentRoot,
        ]);
    }

    if (!is_file($migratedRulesPath) || is_file($legacyRulesPath)) {
        delement_antivirus_runtime_fail('Legacy runtime file was not migrated safely', [
            'runtime_path' => $runtimePath,
            'migrated_rules_exists' => is_file($migratedRulesPath),
            'legacy_rules_exists' => is_file($legacyRulesPath),
        ]);
    }

    if (DIRECTORY_SEPARATOR === '/') {
        $directoryMode = fileperms($runtimePath) & 0777;
        $fileMode = fileperms($migratedRulesPath) & 0777;

        if ($directoryMode !== 0700 || $fileMode !== 0600) {
            delement_antivirus_runtime_fail('Runtime permissions are not strict', [
                'directory_mode' => decoct($directoryMode),
                'file_mode' => decoct($fileMode),
            ]);
        }
    }

    putenv('DELEMENT_ANTIVIRUS_RUNTIME_PATH=' . $configuredWebRootPath);
    putenv('DELEMENT_ANTIVIRUS_RUNTIME_ALLOW_WEB_ROOT');

    $filteredConfiguredPath = RuntimeDirectory::resolve($moduleRoot, 'sessions');

    if (delement_antivirus_runtime_path_inside($filteredConfiguredPath, $documentRoot)) {
        delement_antivirus_runtime_fail('Configured web-root runtime path was allowed without opt-in', [
            'runtime_path' => $filteredConfiguredPath,
            'document_root' => $documentRoot,
        ]);
    }

    putenv('DELEMENT_ANTIVIRUS_RUNTIME_ALLOW_WEB_ROOT=1');
    $allowedConfiguredPath = RuntimeDirectory::resolve($moduleRoot, 'reports');

    if (!delement_antivirus_runtime_path_inside($allowedConfiguredPath, $documentRoot)) {
        delement_antivirus_runtime_fail('Configured web-root runtime path was not allowed with opt-in', [
            'runtime_path' => $allowedConfiguredPath,
            'document_root' => $documentRoot,
        ]);
    }

    echo json_encode([
        'runtime_path' => $runtimePath,
        'configured_path_filtered' => $filteredConfiguredPath,
        'configured_path_allowed' => $allowedConfiguredPath,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
} finally {
    if ($oldDocumentRoot === null) {
        unset($_SERVER['DOCUMENT_ROOT']);
    } else {
        $_SERVER['DOCUMENT_ROOT'] = $oldDocumentRoot;
    }

    if ($oldRuntimePath === false) {
        putenv('DELEMENT_ANTIVIRUS_RUNTIME_PATH');
    } else {
        putenv('DELEMENT_ANTIVIRUS_RUNTIME_PATH=' . $oldRuntimePath);
    }

    if ($oldAllowWebRoot === false) {
        putenv('DELEMENT_ANTIVIRUS_RUNTIME_ALLOW_WEB_ROOT');
    } else {
        putenv('DELEMENT_ANTIVIRUS_RUNTIME_ALLOW_WEB_ROOT=' . $oldAllowWebRoot);
    }

    delement_antivirus_runtime_remove_tree($root);
}
