<?php

namespace Delement\Antivirus\Bitrix\Resolver;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use Throwable;

class EventHandlerResolver
{
    private $locator;

    public function __construct(ClassMethodLocator $locator = null)
    {
        $this->locator = $locator ?: new ClassMethodLocator();
    }

    public function resolve(array $eventHandler, string $documentRoot): array
    {
        $documentRoot = rtrim(str_replace('\\', '/', $documentRoot), '/');

        if ($documentRoot === '' || !is_dir($documentRoot)) {
            return [];
        }

        $className = trim((string)($eventHandler['TO_CLASS'] ?? ''));
        $methodName = trim((string)($eventHandler['TO_METHOD'] ?? ''));

        if ($methodName === '') {
            return [];
        }

        $matches = [];
        $seen = [];

        foreach ($this->candidateFiles($eventHandler, $documentRoot) as $filePath) {
            $normalized = str_replace('\\', '/', $filePath);
            $key = strtolower($normalized);

            if (isset($seen[$key])) {
                continue;
            }

            $seen[$key] = true;

            if ($this->locator->matches($normalized, $className, $methodName)) {
                $matches[] = $normalized;
            }
        }

        return $matches;
    }

    private function candidateFiles(array $eventHandler, string $documentRoot): array
    {
        $files = [
            $documentRoot . '/local/php_interface/init.php',
            $documentRoot . '/bitrix/php_interface/init.php',
        ];
        $moduleId = $this->safeModuleId((string)($eventHandler['TO_MODULE_ID'] ?? ''));

        if ($moduleId !== '') {
            foreach (['local', 'bitrix'] as $scope) {
                $modulePath = $documentRoot . '/' . $scope . '/modules/' . $moduleId;
                $files[] = $modulePath . '/include.php';

                foreach ($this->phpFilesInDirectory($modulePath . '/lib') as $filePath) {
                    $files[] = $filePath;
                }
            }
        }

        return array_values(array_filter($files, static function (string $filePath): bool {
            return is_file($filePath) && is_readable($filePath);
        }));
    }

    private function phpFilesInDirectory(string $directory): array
    {
        if (!is_dir($directory)) {
            return [];
        }

        $files = [];

        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS)
            );

            foreach ($iterator as $item) {
                if (!$item->isFile()) {
                    continue;
                }

                $path = $item->getPathname();

                if (strtolower(pathinfo($path, PATHINFO_EXTENSION)) === 'php') {
                    $files[] = str_replace('\\', '/', $path);
                }
            }
        } catch (Throwable $exception) {
            return [];
        }

        sort($files, SORT_STRING);

        return $files;
    }

    private function safeModuleId(string $moduleId): string
    {
        $moduleId = trim($moduleId);

        return preg_match('/^[a-zA-Z0-9_.-]+$/', $moduleId) === 1 ? $moduleId : '';
    }
}
