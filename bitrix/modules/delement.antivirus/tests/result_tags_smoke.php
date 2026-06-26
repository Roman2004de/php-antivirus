<?php

use Delement\Antivirus\Detection\Finding;
use Delement\Antivirus\Detection\Severity;
use Delement\Antivirus\Detection\Tags\FindingTagger;
use Delement\Antivirus\Detection\Tags\PathTagger;
use Delement\Antivirus\Detection\Tags\ResultTagger;
use Delement\Antivirus\Detection\Tags\TagCatalog;
use Delement\Antivirus\Scanner\ScanResult;

require_once __DIR__ . '/../lib/Detection/Severity.php';
require_once __DIR__ . '/../lib/Detection/Verdict.php';
require_once __DIR__ . '/../lib/Detection/Finding.php';
require_once __DIR__ . '/../lib/Detection/Tags/TagCatalog.php';
require_once __DIR__ . '/../lib/Detection/Tags/PathTagger.php';
require_once __DIR__ . '/../lib/Detection/Tags/FindingTagger.php';
require_once __DIR__ . '/../lib/Detection/Tags/ResultTagger.php';
require_once __DIR__ . '/../lib/Scanner/ScanResult.php';

function delement_antivirus_result_tags_fail(string $message, array $context = []): void
{
    fwrite(STDERR, $message . PHP_EOL);

    if (!empty($context)) {
        fwrite(STDERR, json_encode($context, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    }

    exit(1);
}

function delement_antivirus_result_tags_assert_contains(array $tags, string $tag, string $message): void
{
    if (!in_array($tag, $tags, true)) {
        delement_antivirus_result_tags_fail($message, [
            'expected' => $tag,
            'tags' => $tags,
        ]);
    }
}

function delement_antivirus_result_tags_assert_not_contains(array $tags, string $tag, string $message): void
{
    if (in_array($tag, $tags, true)) {
        delement_antivirus_result_tags_fail($message, [
            'unexpected' => $tag,
            'tags' => $tags,
        ]);
    }
}

$pathTagger = new PathTagger();
$findingTagger = new FindingTagger();
$resultTagger = new ResultTagger($pathTagger, $findingTagger);
$uploadPath = str_replace('\\', '/', sys_get_temp_dir()) . '/site/upload/test.php';
$pathTags = $pathTagger->tagsForPath($uploadPath);

delement_antivirus_result_tags_assert_contains($pathTags, TagCatalog::PATH_UPLOAD, 'Upload path tag is missing');
delement_antivirus_result_tags_assert_contains($pathTags, TagCatalog::RISK_EXECUTABLE_UPLOAD, 'Executable upload risk tag is missing');
delement_antivirus_result_tags_assert_contains($pathTagger->tagsForPath('/var/www/site/bitrix/admin/index.php'), TagCatalog::PATH_CORE, 'Bitrix admin core tag is missing');
delement_antivirus_result_tags_assert_contains($pathTagger->tagsForPath('/var/www/site/bitrix/modules/main/include.php'), TagCatalog::PATH_CORE, 'Bitrix module core tag is missing');
delement_antivirus_result_tags_assert_not_contains($pathTagger->tagsForPath('/var/www/site/bitrix/cache/menu.php'), TagCatalog::PATH_CORE, 'Bitrix cache must not be marked as core');
delement_antivirus_result_tags_assert_not_contains($pathTagger->tagsForPath('/var/www/site/bitrix/tmp/payload.php'), TagCatalog::PATH_CORE, 'Bitrix tmp must not be marked as core');

$astFinding = $findingTagger->tag(new Finding([
    'signature_id' => 'php_ast_dangerous_call_eval',
    'name' => 'AST eval',
    'category' => 'php_ast',
    'severity' => Severity::CRITICAL,
    'score' => 10,
    'target' => 'ast',
    'rule_type' => 'ast',
]));
$taintFinding = $findingTagger->tag(new Finding([
    'signature_id' => 'taint_request_to_eval',
    'name' => 'Taint eval',
    'category' => 'php_taint',
    'severity' => Severity::CRITICAL,
    'score' => 10,
    'target' => 'taint',
    'rule_type' => 'taint',
    'trace' => ['source' => '$_GET[x]', 'sink' => 'eval'],
]));
$htaccessFinding = $findingTagger->tag(new Finding([
    'signature_id' => 'htaccess_php_handler_for_static_ext',
    'name' => 'Handler',
    'category' => 'htaccess',
    'severity' => Severity::CRITICAL,
    'score' => 10,
    'target' => 'htaccess',
    'rule_type' => 'htaccess',
]));

$resultTags = $resultTagger->tagsForResult($uploadPath, [$astFinding, $taintFinding, $htaccessFinding]);
$untaggedAstFinding = new Finding([
    'signature_id' => 'php_ast_dangerous_call_system',
    'name' => 'AST system',
    'category' => 'php_ast',
    'severity' => Severity::CRITICAL,
    'score' => 9,
    'target' => 'ast',
    'rule_type' => 'ast',
]);
$fallbackTags = $resultTagger->tagsForResult($uploadPath, [$untaggedAstFinding]);

delement_antivirus_result_tags_assert_contains($fallbackTags, TagCatalog::ENGINE_AST, 'Untagged Finding fallback did not calculate AST engine tag');

$scanResult = ScanResult::fromFindings(
    $uploadPath,
    'malicious',
    30,
    Severity::CRITICAL,
    [$astFinding, $taintFinding, $htaccessFinding],
    'report',
    true,
    $resultTags
)->toArray();

$findingTags = [];

foreach ($scanResult['findings'] as $finding) {
    $findingTags = TagCatalog::merge($findingTags, $finding['tags'] ?? []);
}

foreach ([
    TagCatalog::PATH_UPLOAD,
    TagCatalog::RISK_EXECUTABLE_UPLOAD,
    TagCatalog::ENGINE_AST,
    TagCatalog::ENGINE_TAINT,
    TagCatalog::ENGINE_HTACCESS,
    TagCatalog::RISK_HTACCESS_HANDLER,
] as $tag) {
    delement_antivirus_result_tags_assert_contains($scanResult['tags'], $tag, 'ScanResult tag is missing');
}

foreach ([TagCatalog::ENGINE_AST, TagCatalog::ENGINE_TAINT, TagCatalog::ENGINE_HTACCESS] as $tag) {
    delement_antivirus_result_tags_assert_contains($findingTags, $tag, 'Finding tag is missing');
}

$nonRequestTraceTags = $findingTagger->tagsForFindingArray([
    'signature_id' => 'synthetic_trace',
    'category' => 'generic',
    'target' => 'content',
    'trace' => ['source' => 'local variable', 'sink' => 'log'],
]);
$requestTraceTags = $findingTagger->tagsForFindingArray([
    'signature_id' => 'synthetic_trace',
    'category' => 'generic',
    'target' => 'content',
    'trace' => ['source' => '$_POST[\'payload\']', 'sink' => 'log'],
]);

delement_antivirus_result_tags_assert_not_contains($nonRequestTraceTags, TagCatalog::RISK_REQUEST_INPUT, 'Non-request trace must not get request input risk tag');
delement_antivirus_result_tags_assert_contains($requestTraceTags, TagCatalog::RISK_REQUEST_INPUT, 'Request trace source must get request input risk tag');

$syntheticFindings = [
    'agent' => [
        'signature_id' => 'synthetic_agent_payload',
        'category' => 'bitrix_db',
        'target' => 'db_agent',
    ],
    'fingerprint' => [
        'signature_id' => 'synthetic_webshell_fingerprint',
        'category' => 'webshell_fingerprint',
        'target' => 'content',
    ],
    'hash_db' => [
        'signature_id' => 'synthetic_hash_db',
        'category' => 'hash_db',
        'target' => 'content',
    ],
    'entropy' => [
        'signature_id' => 'synthetic_entropy',
        'category' => 'entropy',
        'target' => 'content',
    ],
    'url' => [
        'signature_id' => 'synthetic_url',
        'category' => 'url',
        'target' => 'content',
    ],
];
$expectedSyntheticTags = [
    'agent' => TagCatalog::ENTITY_DB_AGENT,
    'fingerprint' => TagCatalog::ENGINE_FINGERPRINT,
    'hash_db' => TagCatalog::ENGINE_HASH_DB,
    'entropy' => TagCatalog::ENGINE_ENTROPY,
    'url' => TagCatalog::ENGINE_URL,
];

foreach ($syntheticFindings as $name => $finding) {
    $tags = $findingTagger->tagsForFindingArray($finding);
    delement_antivirus_result_tags_assert_contains($tags, $expectedSyntheticTags[$name], 'Synthetic finding tag is missing');
}

$legacyResult = [
    'file_path' => $uploadPath,
    'findings' => [
        [
            'signature_id' => 'legacy_ast',
            'category' => 'php_ast',
            'target' => 'ast',
            'rule_type' => 'ast',
        ],
    ],
];
$taggedLegacyResult = $resultTagger->tagResultArray($legacyResult);

if (empty($taggedLegacyResult['tags']) || empty($taggedLegacyResult['findings'][0]['tags'])) {
    delement_antivirus_result_tags_fail('Legacy result without tags was not tagged safely', [
        'result' => $taggedLegacyResult,
    ]);
}

echo json_encode([
    'result_tags' => 'ok',
    'result' => $scanResult['tags'],
    'finding_tags' => $findingTags,
    'legacy_tags' => $taggedLegacyResult['tags'],
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
