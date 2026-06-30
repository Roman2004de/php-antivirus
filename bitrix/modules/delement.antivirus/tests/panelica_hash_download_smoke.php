<?php

use Delement\Antivirus\Cli\PanelicaImportCommand;
use Delement\Antivirus\Cli\ScanCommand;

require_once __DIR__ . '/../lib/Support/ModuleVersion.php';
require_once __DIR__ . '/../lib/Cli/ArgvParser.php';
require_once __DIR__ . '/../lib/Cli/PanelicaImportCommand.php';
require_once __DIR__ . '/../lib/Cli/ScanCommand.php';
require_once __DIR__ . '/../lib/Detection/Hash/Import/SignatureSourceMetadata.php';
require_once __DIR__ . '/../lib/Detection/Hash/Import/PanelicaImportResult.php';
require_once __DIR__ . '/../lib/Detection/Hash/Import/PanelicaHashNormalizer.php';
require_once __DIR__ . '/../lib/Detection/Hash/Import/PanelicaHashDownloader.php';
require_once __DIR__ . '/../lib/Detection/Hash/Import/PanelicaHashImporter.php';

function delement_antivirus_panelica_download_remove_tree(string $path): void
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

function delement_antivirus_panelica_download_fail(string $message, array $context = []): void
{
    fwrite(STDERR, $message . PHP_EOL);

    if (!empty($context)) {
        fwrite(STDERR, json_encode($context, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    }

    exit(1);
}

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'delement_antivirus_panelica_download_smoke_' . getmypid();
$moduleRoot = $root . DIRECTORY_SEPARATOR . 'module';
$documentRoot = $root . DIRECTORY_SEPARATOR . 'site';
$sourceRoot = $root . DIRECTORY_SEPARATOR . 'panelica_remote';

delement_antivirus_panelica_download_remove_tree($root);

try {
    foreach ([
        $moduleRoot . DIRECTORY_SEPARATOR . 'install',
        $documentRoot,
        $sourceRoot . DIRECTORY_SEPARATOR . 'json',
        $sourceRoot . DIRECTORY_SEPARATOR . 'hashes',
    ] as $directory) {
        if (!mkdir($directory, 0777, true) && !is_dir($directory)) {
            delement_antivirus_panelica_download_fail('Cannot create fixture directory', ['directory' => $directory]);
        }
    }

    file_put_contents($moduleRoot . DIRECTORY_SEPARATOR . 'install' . DIRECTORY_SEPARATOR . 'version.php', "<?php\n\$arModuleVersion = ['VERSION' => '0.0.4'];\n");
    file_put_contents($moduleRoot . DIRECTORY_SEPARATOR . 'default_option.php', "<?php\n\$delement_antivirus_default_option = [];\n");
    file_put_contents($sourceRoot . DIRECTORY_SEPARATOR . 'LICENSE', "MIT License\n\nPermission is hereby granted.\n");

    $hash = str_repeat('c', 64);
    file_put_contents($sourceRoot . DIRECTORY_SEPARATOR . 'json' . DIRECTORY_SEPARATOR . 'hashes.json', json_encode([
        'items' => [
            [
                'hash' => strtoupper($hash),
                'name' => 'Panelica Download Fixture',
                'family' => 'download_fixture',
                'category' => 'webshell',
            ],
        ],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    file_put_contents($sourceRoot . DIRECTORY_SEPARATOR . 'hashes' . DIRECTORY_SEPARATOR . 'sha256.txt', $hash . PHP_EOL);

    $_SERVER['DOCUMENT_ROOT'] = $documentRoot;
    $sourceUrl = 'file://' . str_replace('\\', '/', $sourceRoot);
    $hashesOutput = $root . DIRECTORY_SEPARATOR . 'out' . DIRECTORY_SEPARATOR . 'malware_hashes.json';
    $prefixesOutput = $root . DIRECTORY_SEPARATOR . 'out' . DIRECTORY_SEPARATOR . 'malware_hash_prefixes.json';
    $command = new ScanCommand($documentRoot, [], $moduleRoot);
    $download = $command->execute([
        'scan.php',
        '--download-panelica-hashes',
        '--panelica-download-url=' . $sourceUrl,
        '--malware-hashes-output=' . $hashesOutput,
        '--malware-prefixes-output=' . $prefixesOutput,
        '--json',
    ]);
    $payload = json_decode((string)$download['stdout'], true);
    $hashDb = is_file($hashesOutput) ? json_decode((string)file_get_contents($hashesOutput), true) : [];
    $sourceDirectory = (string)($payload['download']['source_directory'] ?? '');

    if (
        ($download['exit_code'] ?? null) !== PanelicaImportCommand::EXIT_OK
        || !is_array($payload)
        || (string)($payload['status'] ?? '') !== 'ok'
        || (int)($payload['imported'] ?? 0) !== 1
        || (string)($payload['download']['source_url'] ?? '') !== $sourceUrl
        || !in_array('LICENSE', (array)($payload['download']['downloaded'] ?? []), true)
        || !in_array('json/hashes.json', (array)($payload['download']['downloaded'] ?? []), true)
        || !is_file($hashesOutput)
        || !is_file($prefixesOutput)
        || !is_file($sourceDirectory . DIRECTORY_SEPARATOR . 'LICENSE')
        || (string)($hashDb['items'][0]['source'] ?? '') !== 'panelica'
    ) {
        delement_antivirus_panelica_download_fail('Panelica download import failed', [
            'result' => $download,
            'payload' => $payload,
            'hash_db' => $hashDb,
        ]);
    }

    $blocked = $command->execute([
        'scan.php',
        '--download-panelica-hashes',
        '--panelica-download-url=http://example.com/panelica',
        '--json',
    ]);
    $blockedPayload = json_decode((string)$blocked['stdout'], true);

    if (
        ($blocked['exit_code'] ?? null) !== PanelicaImportCommand::EXIT_RUNTIME_ERROR
        || (string)($blockedPayload['error'] ?? '') !== 'panelica_download_url_not_allowed'
    ) {
        delement_antivirus_panelica_download_fail('Panelica download allowlist guard failed', [
            'result' => $blocked,
            'payload' => $blockedPayload,
        ]);
    }

    $blockedSimilarPath = $command->execute([
        'scan.php',
        '--download-panelica-hashes',
        '--panelica-download-url=https://github.com/Panelica/malware-signatures-anything',
        '--json',
    ]);
    $blockedSimilarPathPayload = json_decode((string)$blockedSimilarPath['stdout'], true);

    if (
        ($blockedSimilarPath['exit_code'] ?? null) !== PanelicaImportCommand::EXIT_RUNTIME_ERROR
        || (string)($blockedSimilarPathPayload['error'] ?? '') !== 'panelica_download_url_not_allowed'
    ) {
        delement_antivirus_panelica_download_fail('Panelica download similar-path allowlist guard failed', [
            'result' => $blockedSimilarPath,
            'payload' => $blockedSimilarPathPayload,
        ]);
    }

    echo json_encode([
        'panelica_download' => 'ok',
        'imported' => $payload['imported'],
        'source_url' => $payload['download']['source_url'],
        'downloaded' => $payload['download']['downloaded'],
        'allowlist_guard' => $blockedPayload['error'],
        'similar_path_guard' => $blockedSimilarPathPayload['error'],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
} finally {
    delement_antivirus_panelica_download_remove_tree($root);
}
