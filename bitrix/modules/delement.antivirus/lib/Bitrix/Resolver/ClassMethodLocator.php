<?php

namespace Delement\Antivirus\Bitrix\Resolver;

class ClassMethodLocator
{
    public function matches(string $filePath, string $className, string $methodName): bool
    {
        if ($methodName === '' || !is_file($filePath) || !is_readable($filePath)) {
            return false;
        }

        $content = @file_get_contents($filePath);

        if ($content === false || $content === '') {
            return false;
        }

        if ($className === '') {
            return $this->containsFunction($content, $methodName);
        }

        return $this->containsClass($content, $className) && $this->containsFunction($content, $methodName);
    }

    private function containsClass(string $content, string $className): bool
    {
        $className = trim($className, '\\');
        $parts = explode('\\', $className);
        $shortName = end($parts);
        $shortName = is_string($shortName) ? $shortName : $className;

        if (!$this->isPhpIdentifier($shortName)) {
            return false;
        }

        return preg_match('/\b(?:class|trait)\s+' . preg_quote($shortName, '/') . '\b/i', $content) === 1;
    }

    private function containsFunction(string $content, string $methodName): bool
    {
        $methodName = trim($methodName);

        if (!$this->isPhpIdentifier($methodName)) {
            return false;
        }

        return preg_match('/\bfunction\s+' . preg_quote($methodName, '/') . '\s*\(/i', $content) === 1;
    }

    private function isPhpIdentifier(string $value): bool
    {
        return preg_match('/^[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*$/', $value) === 1;
    }
}
