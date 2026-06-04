<?php

use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\File\FileCollector;

require_once __DIR__ . '/../lib/Config/ScanConfig.php';
require_once __DIR__ . '/../lib/File/FileTypeDetector.php';
require_once __DIR__ . '/../lib/File/FileFilter.php';
require_once __DIR__ . '/../lib/File/FileCollector.php';

function delement_antivirus_scan_profiles_remove_dir(string $path): void
{
    if (!is_dir($path)) {
        return;
    }

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );

    foreach ($iterator as $fileInfo) {
        if ($fileInfo->isDir()) {
            @rmdir($fileInfo->getPathname());
        } else {
            @unlink($fileInfo->getPathname());
        }
    }

    @rmdir($path);
}

function delement_antivirus_scan_profiles_write_file(string $path, string $contents): void
{
    $directory = dirname($path);

    if (!is_dir($directory) && !mkdir($directory, 0777, true) && !is_dir($directory)) {
        throw new RuntimeException('Cannot create fixture directory: ' . $directory);
    }

    if (file_put_contents($path, $contents) === false) {
        throw new RuntimeException('Cannot write fixture file: ' . $path);
    }
}

function delement_antivirus_scan_profiles_normalize(string $path): string
{
    return str_replace('\\', '/', $path);
}

function delement_antivirus_scan_profiles_collect(ScanConfig $config): array
{
    $files = [];

    foreach ((new FileCollector())->collectFromConfig($config) as $filePath) {
        $files[] = delement_antivirus_scan_profiles_normalize((string)$filePath);
    }

    sort($files);

    return $files;
}

function delement_antivirus_scan_profiles_collect_incremental(ScanConfig $config, int $batchSize): array
{
    $collector = new FileCollector();
    $state = $collector->createDiscoveryState($config->getScanPaths());
    $files = [];
    $guard = 0;

    do {
        $step = $collector->collectStep($state, $config, $batchSize);
        $state = $step['state'];

        foreach ($step['files'] as $filePath) {
            $files[] = delement_antivirus_scan_profiles_normalize((string)$filePath);
        }

        $guard++;
    } while (empty($step['complete']) && $guard < 100);

    if ($guard >= 100) {
        throw new RuntimeException('Incremental discovery did not finish');
    }

    sort($files);

    return $files;
}

function delement_antivirus_scan_profiles_assert_contains(array $files, string $path): void
{
    $path = delement_antivirus_scan_profiles_normalize($path);

    if (!in_array($path, $files, true)) {
        throw new RuntimeException('Expected path is missing: ' . $path);
    }
}

function delement_antivirus_scan_profiles_assert_not_contains(array $files, string $path): void
{
    $path = delement_antivirus_scan_profiles_normalize($path);

    if (in_array($path, $files, true)) {
        throw new RuntimeException('Unexpected path was collected: ' . $path);
    }
}

$fixtureRoot = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'delement_antivirus_scan_profiles_' . getmypid();
delement_antivirus_scan_profiles_remove_dir($fixtureRoot);

try {
    delement_antivirus_scan_profiles_write_file($fixtureRoot . '/upload/upload_probe.php', '<?php echo "upload fixture";');
    delement_antivirus_scan_profiles_write_file($fixtureRoot . '/upload/readme.txt', 'upload note');
    delement_antivirus_scan_profiles_write_file($fixtureRoot . '/bitrix/php_interface/init.php', '<?php // bitrix init');
    delement_antivirus_scan_profiles_write_file($fixtureRoot . '/local/php_interface/init.php', '<?php // local init');
    delement_antivirus_scan_profiles_write_file($fixtureRoot . '/local/modules/vendor.module/install.php', '<?php // module install');
    delement_antivirus_scan_profiles_write_file($fixtureRoot . '/index.php', '<?php // root index');
    delement_antivirus_scan_profiles_write_file($fixtureRoot . '/notes.txt', 'text fixture');
    delement_antivirus_scan_profiles_write_file($fixtureRoot . '/dump.sql', 'SELECT 1;');
    delement_antivirus_scan_profiles_write_file($fixtureRoot . '/image.svg', '<svg xmlns="http://www.w3.org/2000/svg"></svg>');
    delement_antivirus_scan_profiles_write_file($fixtureRoot . '/.htaccess', 'Options -Indexes');
    delement_antivirus_scan_profiles_write_file($fixtureRoot . '/payload.susp', 'flagged extension fixture');

    $baseOptions = [
        'document_root' => $fixtureRoot,
        'path' => $fixtureRoot,
        'profile' => ScanConfig::PROFILE_BALANCED,
        'action' => ScanConfig::ACTION_REPORT,
        'dry_run' => true,
        'exclude_paths' => [],
        'max_file_size_mb' => 1,
    ];

    $quickFiles = delement_antivirus_scan_profiles_collect(new ScanConfig($baseOptions + [
        'scan_profile' => ScanConfig::SCAN_PROFILE_QUICK,
    ]));

    delement_antivirus_scan_profiles_assert_contains($quickFiles, $fixtureRoot . '/upload/upload_probe.php');
    delement_antivirus_scan_profiles_assert_contains($quickFiles, $fixtureRoot . '/bitrix/php_interface/init.php');
    delement_antivirus_scan_profiles_assert_contains($quickFiles, $fixtureRoot . '/local/php_interface/init.php');
    delement_antivirus_scan_profiles_assert_contains($quickFiles, $fixtureRoot . '/local/modules/vendor.module/install.php');
    delement_antivirus_scan_profiles_assert_not_contains($quickFiles, $fixtureRoot . '/index.php');
    delement_antivirus_scan_profiles_assert_not_contains($quickFiles, $fixtureRoot . '/upload/readme.txt');

    $standardFiles = delement_antivirus_scan_profiles_collect(new ScanConfig($baseOptions + [
        'scan_profile' => ScanConfig::SCAN_PROFILE_STANDARD,
    ]));

    delement_antivirus_scan_profiles_assert_contains($standardFiles, $fixtureRoot . '/index.php');
    delement_antivirus_scan_profiles_assert_contains($standardFiles, $fixtureRoot . '/upload/upload_probe.php');
    delement_antivirus_scan_profiles_assert_not_contains($standardFiles, $fixtureRoot . '/notes.txt');
    delement_antivirus_scan_profiles_assert_not_contains($standardFiles, $fixtureRoot . '/dump.sql');
    delement_antivirus_scan_profiles_assert_not_contains($standardFiles, $fixtureRoot . '/image.svg');
    delement_antivirus_scan_profiles_assert_not_contains($standardFiles, $fixtureRoot . '/.htaccess');
    delement_antivirus_scan_profiles_assert_not_contains($standardFiles, $fixtureRoot . '/payload.susp');

    $deepFiles = delement_antivirus_scan_profiles_collect(new ScanConfig($baseOptions + [
        'scan_profile' => ScanConfig::SCAN_PROFILE_DEEP,
    ]));
    $deepFilesIncremental = delement_antivirus_scan_profiles_collect_incremental(new ScanConfig($baseOptions + [
        'scan_profile' => ScanConfig::SCAN_PROFILE_DEEP,
    ]), 2);

    delement_antivirus_scan_profiles_assert_contains($deepFiles, $fixtureRoot . '/notes.txt');
    delement_antivirus_scan_profiles_assert_contains($deepFiles, $fixtureRoot . '/dump.sql');
    delement_antivirus_scan_profiles_assert_contains($deepFiles, $fixtureRoot . '/image.svg');
    delement_antivirus_scan_profiles_assert_contains($deepFiles, $fixtureRoot . '/.htaccess');
    delement_antivirus_scan_profiles_assert_contains($deepFiles, $fixtureRoot . '/payload.susp');

    if ($deepFilesIncremental !== $deepFiles) {
        throw new RuntimeException('Incremental discovery result differs from full collection');
    }

    echo json_encode(
        [
            'quick_count' => count($quickFiles),
            'standard_count' => count($standardFiles),
            'deep_count' => count($deepFiles),
            'incremental_deep_count' => count($deepFilesIncremental),
        ],
        JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
    ) . PHP_EOL;
} catch (Throwable $exception) {
    fwrite(STDERR, $exception->getMessage() . PHP_EOL);
    exit(1);
} finally {
    delement_antivirus_scan_profiles_remove_dir($fixtureRoot);
}
