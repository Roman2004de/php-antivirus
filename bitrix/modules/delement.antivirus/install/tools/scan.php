<?php

use Bitrix\Main\Config\Option;
use Bitrix\Main\Loader;
use Delement\Antivirus\Cli\ScanCommand;

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    echo 'cli_only' . PHP_EOL;
    exit(1);
}

$moduleId = 'delement.antivirus';
$runtimeErrorExitCode = 3;
$documentRoot = delement_antivirus_cli_document_root($argv);

if ($documentRoot === '') {
    fwrite(STDERR, 'document_root_not_found' . PHP_EOL);
    exit(1);
}

$_SERVER['DOCUMENT_ROOT'] = $documentRoot;

if (!defined('NO_KEEP_STATISTIC')) {
    define('NO_KEEP_STATISTIC', true);
}

if (!defined('NOT_CHECK_PERMISSIONS')) {
    define('NOT_CHECK_PERMISSIONS', true);
}

require_once $documentRoot . '/bitrix/modules/main/include/prolog_before.php';

if (!Loader::includeModule($moduleId)) {
    delement_antivirus_cli_fail('module_not_loaded', $runtimeErrorExitCode, delement_antivirus_cli_has_json($argv), $moduleId);
}

$moduleRoot = $documentRoot . '/bitrix/modules/' . $moduleId;
$command = new ScanCommand(
    $documentRoot,
    delement_antivirus_cli_module_options($moduleId, $moduleRoot),
    $moduleRoot,
    null,
    null,
    $moduleId
);
$result = $command->execute($argv);

if ($result['stdout'] !== '') {
    fwrite(STDOUT, $result['stdout']);
}

if ($result['stderr'] !== '') {
    fwrite(STDERR, $result['stderr']);
}

exit((int)$result['exit_code']);

function delement_antivirus_cli_document_root(array $argv): string
{
    $documentRoot = null;
    $count = count($argv);

    for ($index = 1; $index < $count; $index++) {
        $argument = (string)$argv[$index];

        if (strpos($argument, '--document-root=') === 0) {
            $documentRoot = substr($argument, 16);
            break;
        }

        if ($argument === '--document-root' && isset($argv[$index + 1])) {
            $documentRoot = (string)$argv[$index + 1];
            break;
        }
    }

    $documentRoot = $documentRoot !== null ? $documentRoot : __DIR__ . '/../../..';
    $realDocumentRoot = realpath($documentRoot);

    return $realDocumentRoot !== false && is_dir($realDocumentRoot) ? rtrim($realDocumentRoot, '/\\') : '';
}

function delement_antivirus_cli_module_options(string $moduleId, string $moduleRoot): array
{
    $defaults = delement_antivirus_cli_module_defaults($moduleRoot);
    $options = [];

    foreach ($defaults as $name => $defaultValue) {
        $options[$name] = Option::get($moduleId, $name, (string)$defaultValue);
    }

    return $options;
}

function delement_antivirus_cli_module_defaults(string $moduleRoot): array
{
    $path = rtrim($moduleRoot, '/\\') . '/default_option.php';
    $delement_antivirus_default_option = [];

    if (is_file($path)) {
        require $path;
    }

    return is_array($delement_antivirus_default_option) ? $delement_antivirus_default_option : [];
}

function delement_antivirus_cli_has_json(array $argv): bool
{
    return in_array('--json', $argv, true);
}

function delement_antivirus_cli_fail(string $error, int $exitCode, bool $json, string $moduleId): void
{
    if ($json) {
        fwrite(STDOUT, json_encode([
            'success' => false,
            'module' => $moduleId,
            'error' => $error,
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    } else {
        fwrite(STDERR, $error . PHP_EOL);
    }

    exit($exitCode);
}
