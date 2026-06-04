<?php

namespace Delement\Antivirus\File;

use Delement\Antivirus\Config\ScanConfig;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;
use FilesystemIterator;

class FileCollector
{
    private const DEFAULT_DISCOVERY_NODE_MULTIPLIER = 25;
    private const MIN_DISCOVERY_NODE_LIMIT = 250;

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

    public function createDiscoveryState(array $paths): array
    {
        $pending = [];

        foreach (array_reverse($paths) as $path) {
            $path = (string)$path;

            if ($path !== '') {
                $pending[] = $path;
            }
        }

        return [
            'pending' => $pending,
            'done' => empty($pending),
        ];
    }

    public function collectStep(array $state, ScanConfig $config, int $limit): array
    {
        $limit = max(1, $limit);
        $nodeLimit = max($limit * self::DEFAULT_DISCOVERY_NODE_MULTIPLIER, self::MIN_DISCOVERY_NODE_LIMIT);
        $visitedNodes = 0;
        $files = [];
        $pending = isset($state['pending']) && is_array($state['pending'])
            ? array_values($state['pending'])
            : [];

        while (!empty($pending) && count($files) < $limit && $visitedNodes < $nodeLimit) {
            $path = (string)array_pop($pending);
            $visitedNodes++;

            if (!file_exists($path)) {
                if ($config->ignoresMissingScanPaths()) {
                    continue;
                }

                throw new RuntimeException('scan_path_not_found');
            }

            if (is_file($path)) {
                if ($this->filter->isAllowed($path, $config)) {
                    $files[] = $path;
                }

                continue;
            }

            if (!is_dir($path)) {
                throw new RuntimeException('scan_path_not_regular_file_or_directory');
            }

            if (is_link($path)) {
                continue;
            }

            if ($this->filter->isExcluded($path, $config)) {
                continue;
            }

            $children = $this->listChildren($path);

            foreach (array_reverse($children) as $childPath) {
                $pending[] = $childPath;
            }
        }

        $state = [
            'pending' => $pending,
            'done' => empty($pending),
        ];

        return [
            'files' => $files,
            'state' => $state,
            'complete' => (bool)$state['done'],
        ];
    }

    private function listChildren(string $path): array
    {
        $items = @scandir($path);

        if ($items === false) {
            throw new RuntimeException('directory_read_failed');
        }

        $children = [];

        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }

            $children[] = $path . DIRECTORY_SEPARATOR . $item;
        }

        return $children;
    }

    private function normalizePath(string $path): string
    {
        return str_replace('\\', '/', strtolower(rtrim($path, '/\\')));
    }
}
