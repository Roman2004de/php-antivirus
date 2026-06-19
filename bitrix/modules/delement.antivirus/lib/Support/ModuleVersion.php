<?php

namespace Delement\Antivirus\Support;

class ModuleVersion
{
    public const DEFAULT_VERSION = '0.0.0';
    public const DEFAULT_VERSION_DATE = '1970-01-01 00:00:00';

    public static function get(string $moduleRoot = null): array
    {
        $moduleRoot = $moduleRoot ?: dirname(__DIR__, 2);
        $path = rtrim($moduleRoot, '/\\') . DIRECTORY_SEPARATOR . 'install' . DIRECTORY_SEPARATOR . 'version.php';
        $arModuleVersion = [];

        if (is_file($path)) {
            include $path;
        }

        return [
            'VERSION' => isset($arModuleVersion['VERSION']) ? (string)$arModuleVersion['VERSION'] : self::DEFAULT_VERSION,
            'VERSION_DATE' => isset($arModuleVersion['VERSION_DATE']) ? (string)$arModuleVersion['VERSION_DATE'] : self::DEFAULT_VERSION_DATE,
        ];
    }

    public static function version(string $moduleRoot = null): string
    {
        $version = self::get($moduleRoot);

        return $version['VERSION'];
    }
}
