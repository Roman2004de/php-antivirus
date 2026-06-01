<?php

namespace Delement\Antivirus\Detection;

class Severity
{
    public const INFO = 'info';
    public const LOW = 'low';
    public const MEDIUM = 'medium';
    public const HIGH = 'high';
    public const CRITICAL = 'critical';

    private const WEIGHTS = [
        self::INFO => 0,
        self::LOW => 1,
        self::MEDIUM => 2,
        self::HIGH => 3,
        self::CRITICAL => 4,
    ];

    public static function max(string $left, string $right): string
    {
        $leftWeight = isset(self::WEIGHTS[$left]) ? self::WEIGHTS[$left] : 0;
        $rightWeight = isset(self::WEIGHTS[$right]) ? self::WEIGHTS[$right] : 0;

        return $rightWeight > $leftWeight ? $right : $left;
    }
}
