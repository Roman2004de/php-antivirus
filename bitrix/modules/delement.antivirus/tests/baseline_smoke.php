<?php

use Delement\Antivirus\Cli\ScanCommand;

require_once __DIR__ . '/../lib/Storage/RuntimeDirectory.php';
require_once __DIR__ . '/../lib/Support/ModuleVersion.php';
require_once __DIR__ . '/../lib/Cli/ArgvParser.php';
require_once __DIR__ . '/../lib/Cli/ScanCommand.php';
require_once __DIR__ . '/../lib/Config/ScanConfig.php';
require_once __DIR__ . '/../lib/File/FileTypeDetector.php';
require_once __DIR__ . '/../lib/File/FileFilter.php';
require_once __DIR__ . '/../lib/Detection/Severity.php';
require_once __DIR__ . '/../lib/Detection/Verdict.php';
require_once __DIR__ . '/../lib/Detection/Finding.php';
require_once __DIR__ . '/../lib/Scanner/ScanResult.php';
require_once __DIR__ . '/../lib/Baseline/BaselineRecord.php';
require_once __DIR__ . '/../lib/Baseline/BaselineStorage.php';
require_once __DIR__ . '/../lib/Detection/Baseline/BaselineFindingFactory.php';
require_once __DIR__ . '/../lib/Detection/Baseline/BaselineAnalyzer.php';
require_once __DIR__ . '/../lib/Baseline/BaselineManager.php';

function delement_antivirus_baseline_smoke_remove_tree(string $path): void
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

function delement_antivirus_baseline_smoke_fail(string $message, array $context = []): void
{
    fwrite(STDERR, $message . PHP_EOL);

    if (!empty($context)) {
        fwrite(STDERR, json_encode($context, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL);
    }

    exit(1);
}

function delement_antivirus_baseline_smoke_payload(array $result): array
{
    $payload = json_decode((string)($result['stdout'] ?? ''), true);

    return is_array($payload) ? $payload : [];
}

function delement_antivirus_baseline_smoke_find(array $payload, string $signatureId, string $fileName): array
{
    foreach ((array)($payload['results'] ?? []) as $result) {
        $filePath = (string)($result['file_path'] ?? '');

        if ($fileName !== '' && basename($filePath) !== $fileName) {
            continue;
        }

        foreach ((array)($result['findings'] ?? []) as $finding) {
            if (is_array($finding) && (string)($finding['signature_id'] ?? '') === $signatureId) {
                return $finding;
            }
        }
    }

    return [];
}

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'delement_antivirus_baseline_smoke_' . getmypid();
$documentRoot = $root . DIRECTORY_SEPARATOR . 'site';
$moduleRoot = $root . DIRECTORY_SEPARATOR . 'module';

delement_antivirus_baseline_smoke_remove_tree($root);

try {
    foreach ([$documentRoot, $moduleRoot . DIRECTORY_SEPARATOR . 'install'] as $directory) {
        if (!mkdir($directory, 0777, true) && !is_dir($directory)) {
            delement_antivirus_baseline_smoke_fail('Cannot create fixture directory', ['directory' => $directory]);
        }
    }

    file_put_contents($moduleRoot . DIRECTORY_SEPARATOR . 'install' . DIRECTORY_SEPARATOR . 'version.php', "<?php\n\$arModuleVersion = ['VERSION' => '0.0.4'];\n");
    file_put_contents($moduleRoot . DIRECTORY_SEPARATOR . 'default_option.php', "<?php\n\$delement_antivirus_default_option = [];\n");

    $trackedPath = $documentRoot . DIRECTORY_SEPARATOR . 'tracked.php';
    $deletedPath = $documentRoot . DIRECTORY_SEPARATOR . 'deleted.php';
    $whitespacePath = $documentRoot . DIRECTORY_SEPARATOR . 'whitespace.php';
    file_put_contents($trackedPath, "<?php\necho 1;\n");
    file_put_contents($deletedPath, "<?php\necho 'delete';\n");
    file_put_contents($whitespacePath, "<?php\necho 1;\n");

    $_SERVER['DOCUMENT_ROOT'] = $documentRoot;
    $command = new ScanCommand($documentRoot, [], $moduleRoot);

    $create = $command->execute([
        'scan.php',
        '--baseline-create',
        '--path=' . $documentRoot,
        '--document-root=' . $documentRoot,
        '--json',
    ]);
    $createPayload = delement_antivirus_baseline_smoke_payload($create);

    if (($create['exit_code'] ?? null) !== ScanCommand::EXIT_OK || (int)($createPayload['baseline_records'] ?? 0) !== 3) {
        delement_antivirus_baseline_smoke_fail('Baseline create failed', [
            'result' => $create,
            'payload' => $createPayload,
        ]);
    }

    file_put_contents($trackedPath, "<?php\necho 2;\n");
    file_put_contents($whitespacePath, "<?php    echo 1;\n");
    @unlink($deletedPath);
    file_put_contents($documentRoot . DIRECTORY_SEPARATOR . 'new.php', "<?php\necho 'new';\n");

    $check = $command->execute([
        'scan.php',
        '--baseline-check',
        '--path=' . $documentRoot,
        '--document-root=' . $documentRoot,
        '--json',
    ]);
    $checkPayload = delement_antivirus_baseline_smoke_payload($check);
    $whitespaceFinding = delement_antivirus_baseline_smoke_find($checkPayload, 'baseline_modified_file', 'whitespace.php');

    if (
        ($check['exit_code'] ?? null) !== ScanCommand::EXIT_FINDINGS
        || (int)($checkPayload['new_files'] ?? 0) !== 1
        || (int)($checkPayload['modified_files'] ?? 0) !== 2
        || (int)($checkPayload['deleted_files'] ?? 0) !== 1
        || !array_key_exists('normalized_hash_changed', (array)($whitespaceFinding['trace'] ?? []))
        || $whitespaceFinding['trace']['normalized_hash_changed'] !== false
    ) {
        delement_antivirus_baseline_smoke_fail('Baseline check did not detect expected changes', [
            'result' => $check,
            'payload' => $checkPayload,
            'whitespace_finding' => $whitespaceFinding,
        ]);
    }

    $updateWithoutForce = $command->execute([
        'scan.php',
        '--baseline-update',
        '--path=' . $documentRoot,
        '--document-root=' . $documentRoot,
        '--json',
    ]);
    $updateWithoutForcePayload = delement_antivirus_baseline_smoke_payload($updateWithoutForce);

    if (
        ($updateWithoutForce['exit_code'] ?? null) !== ScanCommand::EXIT_USAGE
        || (string)($updateWithoutForcePayload['error'] ?? '') !== 'cli_force_required_for_baseline_update'
    ) {
        delement_antivirus_baseline_smoke_fail('Baseline update must require --force', [
            'result' => $updateWithoutForce,
            'payload' => $updateWithoutForcePayload,
        ]);
    }

    $update = $command->execute([
        'scan.php',
        '--baseline-update',
        '--force',
        '--path=' . $documentRoot,
        '--document-root=' . $documentRoot,
        '--json',
    ]);
    $updatePayload = delement_antivirus_baseline_smoke_payload($update);

    if (($update['exit_code'] ?? null) !== ScanCommand::EXIT_OK || (int)($updatePayload['baseline_records'] ?? 0) !== 3) {
        delement_antivirus_baseline_smoke_fail('Baseline update failed', [
            'result' => $update,
            'payload' => $updatePayload,
        ]);
    }

    $cleanCheck = $command->execute([
        'scan.php',
        '--baseline-check',
        '--path=' . $documentRoot,
        '--document-root=' . $documentRoot,
        '--json',
    ]);
    $cleanPayload = delement_antivirus_baseline_smoke_payload($cleanCheck);

    if (($cleanCheck['exit_code'] ?? null) !== ScanCommand::EXIT_OK || (int)($cleanPayload['changed_files'] ?? -1) !== 0) {
        delement_antivirus_baseline_smoke_fail('Baseline check after update must be clean', [
            'result' => $cleanCheck,
            'payload' => $cleanPayload,
        ]);
    }

    echo json_encode([
        'baseline' => 'ok',
        'created_records' => $createPayload['baseline_records'],
        'changed_files' => $checkPayload['changed_files'],
        'new_files' => $checkPayload['new_files'],
        'modified_files' => $checkPayload['modified_files'],
        'deleted_files' => $checkPayload['deleted_files'],
        'normalized_hash_changed' => $whitespaceFinding['trace']['normalized_hash_changed'],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL;
} finally {
    delement_antivirus_baseline_smoke_remove_tree($root);
}
