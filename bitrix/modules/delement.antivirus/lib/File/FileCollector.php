<?php

namespace Delement\Antivirus\File;

use Delement\Antivirus\Config\ScanConfig;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;
use FilesystemIterator;

class FileCollector
{
    private $filter;

    public function __construct(FileFilter $filter = null)
    {
        $this->filter = $filter ?: new FileFilter();
    }

    public function collect(string $path, ScanConfig $config): iterable
    {
        if (!file_exists($path)) {
            throw new RuntimeException('scan_path_not_found');
        }

        if (is_file($path)) {
            if ($this->filter->isAllowed($path, $config)) {
                yield $path;
            }

            return;
        }

        if (!is_dir($path)) {
            throw new RuntimeException('scan_path_not_regular_file_or_directory');
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $fileInfo) {
            $filePath = $fileInfo->getPathname();

            if ($fileInfo->isDir()) {
                continue;
            }

            if ($this->filter->isAllowed($filePath, $config)) {
                yield $filePath;
            }
        }
    }

    public function collectFromConfig(ScanConfig $config): iterable
    {
        $hasExistingPath = false;
        $seen = [];

        foreach ($config->getScanPaths() as $path) {
            if (!file_exists($path)) {
                if ($config->ignoresMissingScanPaths()) {
                    continue;
                }

                throw new RuntimeException('scan_path_not_found');
            }

            $hasExistingPath = true;

            foreach ($this->collect($path, $config) as $filePath) {
                $key = $this->normalizePath((string)$filePath);

                if (isset($seen[$key])) {
                    continue;
                }

                $seen[$key] = true;
                yield $filePath;
            }
        }

        if (!$hasExistingPath) {
            throw new RuntimeException('scan_paths_not_found');
        }
    }

    private function normalizePath(string $path): string
    {
        return str_replace('\\', '/', strtolower(rtrim($path, '/\\')));
    }
}
