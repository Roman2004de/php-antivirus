<?php

use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\File\FileFilter;

require_once __DIR__ . '/../lib/Config/ScanConfig.php';
require_once __DIR__ . '/../lib/File/FileTypeDetector.php';
require_once __DIR__ . '/../lib/File/FileFilter.php';

$filter = new FileFilter();
$config = new ScanConfig([
    'path' => '/var/www/site',
    'exclude_paths' => [
        '/var/www/site/bitrix/cache',
        '/var/www/site/upload/resize_cache/',
    ],
]);

$cases = [
    '/var/www/site/bitrix/cache' => true,
    '/var/www/site/bitrix/cache/data/file.php' => true,
    '/var/www/site/upload/resize_cache/image.php' => true,
    '/var/www/site/bitrix/cache-old/file.php' => false,
    '/var/www/site/local/bitrix/cache/file.php' => false,
    '/var/www/site/upload/resize_cache_copy/image.php' => false,
];

foreach ($cases as $path => $expected) {
    $actual = $filter->isExcluded($path, $config);

    if ($actual !== $expected) {
        fwrite(STDERR, json_encode([
            'path' => $path,
            'expected' => $expected,
            'actual' => $actual,
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
        exit(1);
    }
}

echo json_encode([
    'cases' => count($cases),
    'status' => 'ok',
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
