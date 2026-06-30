<?php

use Delement\Antivirus\Cli\PanelicaImportCommand;
use Delement\Antivirus\Cli\ScanCommand;
use Delement\Antivirus\Detection\Hash\Import\PanelicaHashImporter;

require_once __DIR__ . '/../lib/Support/ModuleVersion.php';
require_once __DIR__ . '/../lib/Cli/ArgvParser.php';
require_once __DIR__ . '/../lib/Cli/PanelicaImportCommand.php';
require_once __DIR__ . '/../lib/Cli/ScanCommand.php';
require_once __DIR__ . '/../lib/Detection/Hash/Import/SignatureSourceMetadata.php';
require_once __DIR__ . '/../lib/Detection/Hash/Import/PanelicaImportResult.php';
require_once __DIR__ . '/../lib/Detection/Hash/Import/PanelicaHashNormalizer.php';
require_once __DIR__ . '/../lib/Detection/Hash/Import/PanelicaHashDownloader.php';
require_once __DIR__ . '/../lib/Detection/Hash/Import/PanelicaHashImporter.php';

function delement_antivirus_panelica_import_remove_tree(string $path): void
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

function delement_antivirus_panelica_import_fail(string $message, array $context = []): void
{
    fwrite(STDERR, $message . PHP_EOL);

    if (!empty($context)) {
        fwrite(STDERR, json_encode($context, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    }

    exit(1);
}

function delement_antivirus_panelica_import_write_json(string $path, array $data): void
{
    $dir = dirname($path);

    if (!is_dir($dir) && !mkdir($dir, 0777, true) && !is_dir($dir)) {
        delement_antivirus_panelica_import_fail('Cannot create JSON fixture directory');
    }

    file_put_contents($path, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
}

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'delement_antivirus_panelica_import_smoke_' . getmypid();
$moduleRoot = $root . DIRECTORY_SEPARATOR . 'module';
$documentRoot = $root . DIRECTORY_SEPARATOR . 'site';
$sourceRoot = $root . DIRECTORY_SEPARATOR . 'panelica';
$fallbackRoot = $root . DIRECTORY_SEPARATOR . 'panelica_fallback';

delement_antivirus_panelica_import_remove_tree($root);

try {
    foreach ([
        $moduleRoot . DIRECTORY_SEPARATOR . 'install',
        $documentRoot,
        $sourceRoot . DIRECTORY_SEPARATOR . 'json',
        $sourceRoot . DIRECTORY_SEPARATOR . 'hashes',
        $fallbackRoot . DIRECTORY_SEPARATOR . 'hashes',
    ] as $directory) {
        if (!mkdir($directory, 0777, true) && !is_dir($directory)) {
            delement_antivirus_panelica_import_fail('Cannot create fixture directory', ['directory' => $directory]);
        }
    }

    file_put_contents($moduleRoot . DIRECTORY_SEPARATOR . 'install' . DIRECTORY_SEPARATOR . 'version.php', "<?php\n\$arModuleVersion = ['VERSION' => '0.0.4'];\n");
    file_put_contents($moduleRoot . DIRECTORY_SEPARATOR . 'default_option.php', "<?php\n\$delement_antivirus_default_option = [];\n");
    file_put_contents($sourceRoot . DIRECTORY_SEPARATOR . 'LICENSE', "MIT License\n\nPermission is hereby granted.\n");
    file_put_contents($fallbackRoot . DIRECTORY_SEPARATOR . 'LICENSE', "MIT License\n\nPermission is hereby granted.\n");

    $hashA = strtoupper(str_repeat('a', 64));
    $hashB = strtoupper(str_repeat('b', 64));
    $hashesOutput = $root . DIRECTORY_SEPARATOR . 'out' . DIRECTORY_SEPARATOR . 'malware_hashes.json';
    $prefixesOutput = $root . DIRECTORY_SEPARATOR . 'out' . DIRECTORY_SEPARATOR . 'malware_hash_prefixes.json';

    delement_antivirus_panelica_import_write_json($sourceRoot . DIRECTORY_SEPARATOR . 'json' . DIRECTORY_SEPARATOR . 'hashes.json', [
        [
            'sha256' => $hashA,
            'name' => 'Panelica Fixture',
            'family' => 'fixture_family',
            'category' => 'backdoor',
            'severity' => 'medium',
            'tags' => ['custom tag'],
        ],
        [
            'hash' => strtolower($hashA),
            'name' => 'Duplicate Fixture',
        ],
        [
            'hash' => 'not-a-sha256',
        ],
    ]);
    file_put_contents($sourceRoot . DIRECTORY_SEPARATOR . 'hashes' . DIRECTORY_SEPARATOR . 'sha256.txt', strtolower($hashB) . PHP_EOL);

    $importer = new PanelicaHashImporter($moduleRoot);
    $result = $importer->import($sourceRoot, [
        'hashes_output' => $hashesOutput,
        'prefixes_output' => $prefixesOutput,
        'prefix_length' => 8,
        'source_commit' => 'fixture-commit',
    ]);

    if (!$result->isSuccess()) {
        delement_antivirus_panelica_import_fail('Panelica JSON import failed', ['result' => $result->toArray()]);
    }

    $hashDb = json_decode((string)file_get_contents($hashesOutput), true);
    $prefixDb = json_decode((string)file_get_contents($prefixesOutput), true);
    $item = $hashDb['items'][0] ?? [];

    if (
        (int)($result->toArray()['imported'] ?? 0) !== 1
        || (int)($result->toArray()['skipped_invalid'] ?? 0) !== 1
        || (int)($result->toArray()['skipped_duplicates'] ?? 0) !== 1
        || (string)($item['hash'] ?? '') !== strtolower($hashA)
        || (string)($item['severity'] ?? '') !== 'high'
        || !in_array('backdoor', (array)($item['tags'] ?? []), true)
        || !in_array('panelica', (array)($item['tags'] ?? []), true)
        || (string)($hashDb['source']['license'] ?? '') !== 'MIT'
        || (string)($hashDb['source']['source_commit'] ?? '') !== 'fixture-commit'
        || (int)($prefixDb['prefix_length'] ?? 0) !== 8
        || ($prefixDb['prefixes'] ?? []) !== [substr(strtolower($hashA), 0, 8)]
        || !is_file($moduleRoot . DIRECTORY_SEPARATOR . 'var' . DIRECTORY_SEPARATOR . 'signatures' . DIRECTORY_SEPARATOR . 'sources' . DIRECTORY_SEPARATOR . 'panelica' . DIRECTORY_SEPARATOR . 'LICENSE')
        || !is_file($moduleRoot . DIRECTORY_SEPARATOR . 'var' . DIRECTORY_SEPARATOR . 'signatures' . DIRECTORY_SEPARATOR . 'sources' . DIRECTORY_SEPARATOR . 'panelica' . DIRECTORY_SEPARATOR . 'import_metadata.json')
    ) {
        delement_antivirus_panelica_import_fail('Panelica JSON import output is wrong', [
            'result' => $result->toArray(),
            'hash_db' => $hashDb,
            'prefix_db' => $prefixDb,
        ]);
    }

    $fallbackHashesOutput = $root . DIRECTORY_SEPARATOR . 'fallback' . DIRECTORY_SEPARATOR . 'malware_hashes.json';
    $fallbackPrefixesOutput = $root . DIRECTORY_SEPARATOR . 'fallback' . DIRECTORY_SEPARATOR . 'malware_hash_prefixes.json';
    file_put_contents($fallbackRoot . DIRECTORY_SEPARATOR . 'hashes' . DIRECTORY_SEPARATOR . 'sha256.txt', implode(PHP_EOL, [
        '# comment',
        $hashB,
        strtolower($hashB),
        'bad-hash',
        '',
    ]));

    $fallback = $importer->import($fallbackRoot, [
        'hashes_output' => $fallbackHashesOutput,
        'prefixes_output' => $fallbackPrefixesOutput,
    ]);
    $fallbackDb = json_decode((string)file_get_contents($fallbackHashesOutput), true);

    if (
        !$fallback->isSuccess()
        || (string)$fallback->getSourceUsed() !== 'hashes/sha256.txt'
        || (int)($fallback->toArray()['imported'] ?? 0) !== 1
        || (int)($fallback->toArray()['skipped_invalid'] ?? 0) !== 1
        || (int)($fallback->toArray()['skipped_duplicates'] ?? 0) !== 1
        || (string)($fallbackDb['items'][0]['name'] ?? '') !== 'Panelica known PHP malware'
        || (string)($fallbackDb['items'][0]['family'] ?? '') !== 'unknown'
    ) {
        delement_antivirus_panelica_import_fail('Panelica sha256.txt fallback import failed', [
            'result' => $fallback->toArray(),
            'hash_db' => $fallbackDb,
        ]);
    }

    $_SERVER['DOCUMENT_ROOT'] = $documentRoot;
    $command = new ScanCommand($documentRoot, [], $moduleRoot);
    $cliHashesOutput = $root . DIRECTORY_SEPARATOR . 'cli' . DIRECTORY_SEPARATOR . 'malware_hashes.json';
    $cliPrefixesOutput = $root . DIRECTORY_SEPARATOR . 'cli' . DIRECTORY_SEPARATOR . 'malware_hash_prefixes.json';
    $cli = $command->execute([
        'scan.php',
        '--import-panelica-hashes=' . $sourceRoot,
        '--malware-hashes-output=' . $cliHashesOutput,
        '--malware-prefixes-output=' . $cliPrefixesOutput,
        '--panelica-source-commit=cli-fixture',
        '--json',
    ]);
    $cliPayload = json_decode((string)$cli['stdout'], true);

    if (
        ($cli['exit_code'] ?? null) !== PanelicaImportCommand::EXIT_OK
        || !is_array($cliPayload)
        || (string)($cliPayload['status'] ?? '') !== 'ok'
        || (string)($cliPayload['source_used'] ?? '') !== 'json/hashes.json'
        || (int)($cliPayload['imported'] ?? 0) !== 1
        || !is_file($cliHashesOutput)
        || !is_file($cliPrefixesOutput)
    ) {
        delement_antivirus_panelica_import_fail('Panelica CLI import failed', [
            'cli' => $cli,
            'payload' => $cliPayload,
        ]);
    }

    echo json_encode([
        'panelica_import' => 'ok',
        'json_imported' => $result->getImported(),
        'fallback_imported' => $fallback->getImported(),
        'cli_imported' => $cliPayload['imported'],
        'source_used' => $result->getSourceUsed(),
        'license_copied' => true,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
} finally {
    delement_antivirus_panelica_import_remove_tree($root);
}
