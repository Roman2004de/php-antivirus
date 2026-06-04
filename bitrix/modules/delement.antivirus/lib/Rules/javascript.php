<?php

use Delement\Antivirus\Detection\Severity;

return [
    [
        'id' => 'js_from_char_code',
        'category' => 'javascript_injection',
        'severity' => Severity::MEDIUM,
        'score' => 3,
        'pattern' => '/fromCharCode\s*\(/i',
        'extensions' => ['js', 'html', 'htm', 'php', 'phtml', 'tpl'],
    ],
    [
        'id' => 'js_legacy_unescape',
        'category' => 'javascript_injection',
        'severity' => Severity::MEDIUM,
        'score' => 3,
        'pattern' => '/\bunescape\s*\(/i',
        'extensions' => ['js', 'html', 'htm', 'php', 'phtml', 'tpl'],
    ],
    [
        'id' => 'js_atob_payload',
        'category' => 'javascript_injection',
        'severity' => Severity::LOW,
        'score' => 2,
        'pattern' => '/\batob\s*\(/i',
        'extensions' => ['js', 'html', 'htm', 'php', 'phtml', 'tpl'],
    ],
    [
        'id' => 'js_timer_code',
        'category' => 'javascript_injection',
        'severity' => Severity::LOW,
        'score' => 2,
        'pattern' => '/\b(setTimeout|setInterval)\s*\(/i',
        'extensions' => ['js', 'html', 'htm', 'php', 'phtml', 'tpl'],
    ],
];
