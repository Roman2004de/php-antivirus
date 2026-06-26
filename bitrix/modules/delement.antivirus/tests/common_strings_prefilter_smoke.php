<?php

use Delement\Antivirus\Cli\ArgvParser;
use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\Detection\RuleEngine;
use Delement\Antivirus\Detection\Severity;

require_once __DIR__ . '/../lib/Cli/ArgvParser.php';
require_once __DIR__ . '/../lib/Config/ScanConfig.php';
require_once __DIR__ . '/../lib/Detection/Severity.php';
require_once __DIR__ . '/../lib/Detection/Finding.php';
require_once __DIR__ . '/../lib/Detection/RuleEngine.php';

function delement_antivirus_common_prefilter_fail(string $message, array $context = []): void
{
    fwrite(STDERR, $message . PHP_EOL);

    if (!empty($context)) {
        fwrite(STDERR, json_encode($context, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    }

    exit(1);
}

function delement_antivirus_common_prefilter_config($enabled): ScanConfig
{
    return new ScanConfig([
        'path' => sys_get_temp_dir(),
        'scan_profile' => ScanConfig::SCAN_PROFILE_STANDARD,
        'profile' => ScanConfig::PROFILE_BALANCED,
        'action' => ScanConfig::ACTION_REPORT,
        'dry_run' => true,
        'enable_common_strings_prefilter' => $enabled,
    ]);
}

function delement_antivirus_common_prefilter_count(array $rules, string $content, $enabled = true): int
{
    $engine = new RuleEngine($rules);

    return count($engine->analyzeContent(
        $content,
        sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'fixture.php',
        delement_antivirus_common_prefilter_config($enabled)
    ));
}

$baseRule = [
    'id' => 'synthetic_payload',
    'category' => 'synthetic',
    'severity' => Severity::HIGH,
    'score' => 5,
    'pattern' => '/marker_payload/',
    'extensions' => ['php'],
];

$withoutPrefilter = delement_antivirus_common_prefilter_count([$baseRule], '<?php marker_payload();');

if ($withoutPrefilter !== 1) {
    delement_antivirus_common_prefilter_fail('Rule without common_strings must work as before');
}

$missingMarkerRule = $baseRule;
$missingMarkerRule['common_strings'] = ['missing_marker'];
$withMissingMarker = delement_antivirus_common_prefilter_count([$missingMarkerRule], '<?php marker_payload();');
$disabledPrefilter = delement_antivirus_common_prefilter_count([$missingMarkerRule], '<?php marker_payload();', false);

if ($withMissingMarker !== 0 || $disabledPrefilter !== 1) {
    delement_antivirus_common_prefilter_fail('Prefilter enable/disable behavior is wrong', [
        'with_missing_marker' => $withMissingMarker,
        'disabled_prefilter' => $disabledPrefilter,
    ]);
}

$missingValuesRule = $baseRule;
$missingValuesRule['common_strings'] = [
    'mode' => 'all',
];
$missingValuesCount = delement_antivirus_common_prefilter_count([$missingValuesRule], '<?php marker_payload();');

if ($missingValuesCount !== 1) {
    delement_antivirus_common_prefilter_fail('Structured common_strings without values must be pass-through');
}

$allRule = [
    'id' => 'synthetic_all',
    'category' => 'synthetic',
    'severity' => Severity::HIGH,
    'score' => 5,
    'pattern' => '/needle_one\s*\(\s*needle_two/i',
    'common_strings' => [
        'mode' => 'all',
        'values' => ['needle_one', 'needle_two'],
    ],
    'extensions' => ['php'],
];
$allIncomplete = delement_antivirus_common_prefilter_count([$allRule], '<?php needle_one($payload);');
$allComplete = delement_antivirus_common_prefilter_count([$allRule], '<?php needle_one(needle_two($payload));');

if ($allIncomplete !== 0 || $allComplete !== 1) {
    delement_antivirus_common_prefilter_fail('mode=all behavior is wrong', [
        'all_incomplete' => $allIncomplete,
        'all_complete' => $allComplete,
    ]);
}

$anyRule = [
    'id' => 'synthetic_any',
    'category' => 'synthetic',
    'severity' => Severity::HIGH,
    'score' => 5,
    'pattern' => '/\b(alpha_call|beta_call)\s*\(/i',
    'common_strings' => ['alpha_call', 'beta_call'],
    'extensions' => ['php'],
];
$anyMatched = delement_antivirus_common_prefilter_count([$anyRule], '<?php beta_call($payload);');

if ($anyMatched !== 1) {
    delement_antivirus_common_prefilter_fail('Short common_strings format must behave as mode=any');
}

$parsed = (new ArgvParser())->parse(['scan.php', '--disable-prefilter']);

if (empty($parsed['flags']['disable-prefilter'])) {
    delement_antivirus_common_prefilter_fail('CLI --disable-prefilter flag was not parsed', [
        'parsed' => $parsed,
    ]);
}

echo json_encode([
    'common_strings_prefilter' => 'ok',
    'without_prefilter_rule' => $withoutPrefilter,
    'with_missing_marker' => $withMissingMarker,
    'disabled_prefilter' => $disabledPrefilter,
    'missing_values' => $missingValuesCount,
    'mode_all' => $allComplete,
    'mode_any' => $anyMatched,
    'cli_disable_prefilter' => true,
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
