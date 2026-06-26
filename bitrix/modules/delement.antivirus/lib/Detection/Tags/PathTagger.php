<?php

namespace Delement\Antivirus\Detection\Tags;

class PathTagger
{
    private const EXECUTABLE_UPLOAD_EXTENSIONS = [
        'php' => true,
        'php5' => true,
        'php7' => true,
        'phtml' => true,
    ];

    public function tagsForPath(string $filePath): array
    {
        $path = $this->normalizePath($filePath);
        $tags = [TagCatalog::ENTITY_FILE];

        if ($this->containsSegmentPath($path, '/bitrix/modules/')) {
            $tags[] = TagCatalog::PATH_BITRIX_MODULE;
        }

        if ($this->containsSegmentPath($path, '/local/modules/')) {
            $tags[] = TagCatalog::PATH_LOCAL_MODULE;
        }

        if ($this->containsSegmentPath($path, '/bitrix/php_interface/') || $this->containsSegmentPath($path, '/local/php_interface/')) {
            $tags[] = TagCatalog::PATH_PHP_INTERFACE;
        }

        if ($this->containsSegmentPath($path, '/upload/')) {
            $tags[] = TagCatalog::PATH_UPLOAD;
        }

        if ($this->containsSegmentPath($path, '/bitrix/cache/') || $this->containsSegmentPath($path, '/cache/')) {
            $tags[] = TagCatalog::PATH_CACHE;
        }

        if ($this->containsSegmentPath($path, '/tmp/') || $this->containsSegmentPath($path, '/bitrix/tmp/')) {
            $tags[] = TagCatalog::PATH_TMP;
        }

        if ($this->containsSegmentPath($path, '/vendor/')) {
            $tags[] = TagCatalog::PATH_VENDOR;
        }

        if (
            $this->containsSegmentPath($path, '/local/components/')
            || $this->containsSegmentPath($path, '/local/modules/')
            || $this->containsSegmentPath($path, '/local/php_interface/')
            || $this->containsSegmentPath($path, '/local/templates/')
        ) {
            $tags[] = TagCatalog::PATH_LOCAL;
        }

        if ($this->isBitrixCorePath($path)) {
            $tags[] = TagCatalog::PATH_CORE;
        }

        if ($this->isHiddenPath($path)) {
            $tags[] = TagCatalog::PATH_HIDDEN;
        }

        if (in_array(TagCatalog::PATH_UPLOAD, $tags, true) && isset(self::EXECUTABLE_UPLOAD_EXTENSIONS[$this->extension($path)])) {
            $tags[] = TagCatalog::RISK_EXECUTABLE_UPLOAD;
        }

        return TagCatalog::normalize($tags);
    }

    private function containsSegmentPath(string $path, string $segmentPath): bool
    {
        return strpos($path, $segmentPath) !== false || substr($path, -strlen(rtrim($segmentPath, '/'))) === rtrim($segmentPath, '/');
    }

    private function isHiddenPath(string $path): bool
    {
        foreach (explode('/', trim($path, '/')) as $segment) {
            if ($segment !== '' && strpos($segment, '.') === 0) {
                return true;
            }
        }

        return false;
    }

    private function isBitrixCorePath(string $path): bool
    {
        if ($this->containsSegmentPath($path, '/bitrix/cache/') || $this->containsSegmentPath($path, '/bitrix/tmp/')) {
            return false;
        }

        return $this->containsSegmentPath($path, '/bitrix/modules/')
            || $this->containsSegmentPath($path, '/bitrix/admin/')
            || $this->containsSegmentPath($path, '/bitrix/tools/')
            || $this->containsSegmentPath($path, '/bitrix/php_interface/');
    }

    private function extension(string $path): string
    {
        return strtolower(pathinfo($path, PATHINFO_EXTENSION));
    }

    private function normalizePath(string $path): string
    {
        return '/' . trim(str_replace('\\', '/', strtolower($path)), '/');
    }
}
