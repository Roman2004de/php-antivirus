<?php

namespace Delement\Antivirus\Detection;

class Verdict
{
    public const CLEAN = 'clean';
    public const SKIPPED = 'skipped';
    public const LOW_RISK = 'low_risk';
    public const SUSPICIOUS = 'suspicious';
    public const MALICIOUS = 'malicious';
    public const ERROR = 'error';

    public static function fromScore(int $score, array $thresholds): string
    {
        $suspicious = isset($thresholds['suspicious']) ? (int)$thresholds['suspicious'] : 4;
        $malicious = isset($thresholds['malicious']) ? (int)$thresholds['malicious'] : 8;

        if ($score >= $malicious) {
            return self::MALICIOUS;
        }

        if ($score >= $suspicious) {
            return self::SUSPICIOUS;
        }

        if ($score > 0) {
            return self::LOW_RISK;
        }

        return self::CLEAN;
    }
}
