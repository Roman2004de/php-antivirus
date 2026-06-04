<?php

use Delement\Antivirus\Detection\Severity;

return [
    [
        'id' => 'html_iframe',
        'category' => 'javascript_injection',
        'severity' => Severity::LOW,
        'score' => 2,
        'pattern' => '/<\s*iframe\b/i',
        'extensions' => ['html', 'htm', 'php', 'phtml', 'tpl', 'js'],
    ],
    [
        'id' => 'html_object_embed',
        'category' => 'javascript_injection',
        'severity' => Severity::LOW,
        'score' => 2,
        'pattern' => '/<\s*(object|embed)\b/i',
        'extensions' => ['html', 'htm', 'php', 'phtml', 'tpl', 'js'],
    ],
    [
        'id' => 'html_phishing_form',
        'category' => 'phishing_markup',
        'severity' => Severity::MEDIUM,
        'score' => 4,
        'pattern' => '/<\s*form\b[^>]*action\s*=\s*["\'][^"\']*(login|signin|bank|account|paypal|wallet|metamask|binance)[^"\']*["\']/i',
        'extensions' => ['html', 'htm', 'php', 'phtml', 'tpl'],
    ],
];
