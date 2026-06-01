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
            throw new RuntimeException('Path does not exist: ' . $path);
        }

        if (is_file($path)) {
            if ($this->filter->isAllowed($path, $config)) {
                yield $path;
            }

            return;
        }

        if (!is_dir($path)) {
            throw new RuntimeException('Path is not a regular file or directory: ' . $path);
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
}
