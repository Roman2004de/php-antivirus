<?php

namespace Delement\Antivirus\File;

use Delement\Antivirus\Config\ScanConfig;

class FileFilter
{
    private $typeDetector;

    public function __construct(FileTypeDetector $typeDetector = null)
    {
        $this->typeDetector = $typeDetector ?: new FileTypeDetector();
    }

    public function isAllowed(string $filePath, ScanConfig $config): bool
    {
        if (!is_file($filePath) || !is_readable($filePath)) {
            return false;
        }

        if ($this->isExcluded($filePath, $config)) {
            return false;
        }

        $extension = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));

        if ($extension === '' && basename($filePath) === '.htaccess') {
            $extension = 'htaccess';
        }

        if (!in_array($extension, $config->getExtensions(), true)) {
            return false;
        }

        return !$this->typeDetector->isBinary($filePath);
    }

    public function isExcluded(string $path, ScanConfig $config): bool
    {
        $path = $this->normalizePath($path);

        foreach ($config->getExcludePaths() as $excludePath) {
            $excludePath = $this->normalizePath($excludePath);

            if ($excludePath === '') {
                continue;
            }

            if ($path === $excludePath || strpos($path, $excludePath . '/') === 0) {
                return true;
            }
        }

        return false;
    }

    private function normalizePath(string $path): string
    {
        return str_replace('\\', '/', strtolower(rtrim($path, '/\\')));
    }
}
