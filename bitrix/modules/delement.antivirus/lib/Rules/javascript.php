<?php

use Delement\Antivirus\Detection\Severity;

return [
    [
        'id' => 'js_from_char_code',
        'category' => 'javascript_injection',
        'severity' => Severity::MEDIUM,
        'score' => 3,
        'pattern' => '/fromCharCode\s*\(/i',
        'common_strings' => ['fromCharCode'],
        'extensions' => ['js', 'html', 'htm', 'php', 'phtml', 'tpl'],
    ],
    [
        'id' => 'js_legacy_unescape',
        'category' => 'javascript_injection',
        'severity' => Severity::MEDIUM,
        'score' => 3,
        'pattern' => '/\bunescape\s*\(/i',
        'common_strings' => ['unescape'],
        'extensions' => ['js', 'html', 'htm', 'php', 'phtml', 'tpl'],
    ],
    [
        'id' => 'js_atob_payload',
        'category' => 'javascript_injection',
        'severity' => Severity::LOW,
        'score' => 2,
        'pattern' => '/\batob\s*\(/i',
        'common_strings' => ['atob'],
        'extensions' => ['js', 'html', 'htm', 'php', 'phtml', 'tpl'],
    ],
    [
        'id' => 'js_timer_code',
        'category' => 'javascript_injection',
        'severity' => Severity::LOW,
        'score' => 2,
        'pattern' => '/\b(setTimeout|setInterval)\s*\(/i',
        'common_strings' => ['setTimeout', 'setInterval'],
        'extensions' => ['js', 'html', 'htm', 'php', 'phtml', 'tpl'],
    ],
];
