<?php

use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\Scanner\Scanner;

$vendorAutoload = __DIR__ . '/../vendor/autoload.php';

if (is_file($vendorAutoload)) {
    require_once $vendorAutoload;
}

require_once __DIR__ . '/../lib/Config/ScanConfig.php';
require_once __DIR__ . '/../lib/Detection/Severity.php';
require_once __DIR__ . '/../lib/Detection/Verdict.php';
require_once __DIR__ . '/../lib/Detection/Finding.php';
require_once __DIR__ . '/../lib/Detection/Ast/AstParseResult.php';
require_once __DIR__ . '/../lib/Detection/Ast/AstContext.php';
require_once __DIR__ . '/../lib/Detection/Ast/PhpAstParser.php';
require_once __DIR__ . '/../lib/Detection/Ast/NodeCollector.php';
require_once __DIR__ . '/../lib/Detection/Ast/AstFindingFactory.php';
require_once __DIR__ . '/../lib/Detection/Ast/DangerousCallDetector.php';
require_once __DIR__ . '/../lib/Detection/Ast/DynamicCallDetector.php';
require_once __DIR__ . '/../lib/Detection/Ast/EncodedPayloadDetector.php';
require_once __DIR__ . '/../lib/Detection/Taint/TaintTrace.php';
require_once __DIR__ . '/../lib/Detection/Taint/TaintSourceDetector.php';
require_once __DIR__ . '/../lib/Detection/Taint/TaintPropagator.php';
require_once __DIR__ . '/../lib/Detection/Taint/TaintFindingFactory.php';
require_once __DIR__ . '/../lib/Detection/Taint/TaintSinkDetector.php';
require_once __DIR__ . '/../lib/Detection/Taint/TaintAnalyzer.php';
require_once __DIR__ . '/../lib/Detection/Ast/AstAnalyzer.php';
require_once __DIR__ . '/../lib/Detection/SignatureLoader.php';
require_once __DIR__ . '/../lib/Detection/RuleEngine.php';
require_once __DIR__ . '/../lib/Detection/Detector.php';
require_once __DIR__ . '/../lib/File/FileTypeDetector.php';
require_once __DIR__ . '/../lib/File/FileReader.php';
require_once __DIR__ . '/../lib/File/FileFilter.php';
require_once __DIR__ . '/../lib/File/FileCollector.php';
require_once __DIR__ . '/../lib/Scanner/ScanResult.php';
require_once __DIR__ . '/../lib/Scanner/ScanSummary.php';
require_once __DIR__ . '/../lib/Scanner/Scanner.php';

function delement_antivirus_taint_smoke_remove_tree(string $path): void
{
    if (!is_dir($path)) {
        return;
    }

    $items = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );

    foreach ($items as $item) {
        if ($item->isDir()) {
            @rmdir($item->getPathname());
        } else {
            @unlink($item->getPathname());
        }
    }

    @rmdir($path);
}

function delement_antivirus_taint_smoke_fail(string $message, array $context = []): void
{
    fwrite(STDERR, $message . PHP_EOL);

    if (!empty($context)) {
        fwrite(STDERR, json_encode($context, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    }

    exit(1);
}

if (!class_exists('PhpParser\\ParserFactory')) {
    delement_antivirus_taint_smoke_fail('nikic/php-parser is not available');
}

$fixtureRoot = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'delement_antivirus_taint_smoke_' . getmypid();
delement_antivirus_taint_smoke_remove_tree($fixtureRoot);

try {
    if (!mkdir($fixtureRoot, 0777, true) && !is_dir($fixtureRoot)) {
        delement_antivirus_taint_smoke_fail('Cannot create fixture directory');
    }

    $fixtures = [
        'eval_get.module' => "eval(\$_GET['x']);\n",
        'shell_exec_post.php' => "<?php\n\$cmd = \$_POST['cmd'];\nshell_exec(\$cmd);\n",
        'include_request.php' => "<?php\n\$p = \$_REQUEST['page'];\ninclude \$p;\n",
        'dynamic_callable.php' => "<?php\n\$f = \$_GET['f'];\n\$f(\$_POST['payload']);\n",
        'transform_eval.php' => "<?php\n\$a = \$_POST['x'];\n\$b = base64_decode(\$a);\neval(\$b);\n",
        'php_input_write.php' => "<?php\n\$body = file_get_contents('php://input');\nfile_put_contents('/tmp/payload.php', \$body);\n",
        'curl_url.php' => "<?php\n\$url = filter_input(INPUT_GET, 'url');\ncurl_setopt(\$ch, CURLOPT_URL, \$url);\n",
    ];

    foreach ($fixtures as $name => $contents) {
        file_put_contents($fixtureRoot . DIRECTORY_SEPARATOR . $name, $contents);
    }

    $config = new ScanConfig([
        'path' => $fixtureRoot,
        'scan_profile' => ScanConfig::SCAN_PROFILE_STANDARD,
        'profile' => ScanConfig::PROFILE_BALANCED,
        'action' => ScanConfig::ACTION_REPORT,
        'dry_run' => true,
        'exclude_paths' => [],
        'max_file_size_mb' => 1,
        'enable_ast_analysis' => 'Y',
        'ast_max_file_size' => 1048576,
    ]);
    $summary = (new Scanner())->scan($config)->toArray();
    $byFile = [];
    $signatures = [];

    foreach ($summary['results'] as $result) {
        $name = basename((string)($result['file_path'] ?? ''));
        $byFile[$name] = [];

        foreach ($result['findings'] as $finding) {
            $id = (string)($finding['signature_id'] ?? '');

            if (strpos($id, 'taint_') === 0) {
                $byFile[$name][$id] = $finding;
                $signatures[$id] = true;
            }
        }
    }

    $expectedByFile = [
        'eval_get.module' => 'taint_request_to_eval',
        'shell_exec_post.php' => 'taint_request_to_shell_exec',
        'include_request.php' => 'taint_request_to_include',
        'dynamic_callable.php' => 'taint_request_to_dynamic_call',
        'transform_eval.php' => 'taint_request_to_eval',
        'php_input_write.php' => 'taint_request_to_file_put_contents',
        'curl_url.php' => 'taint_request_to_curl_setopt_url',
    ];
    $missing = [];

    foreach ($expectedByFile as $file => $signatureId) {
        if (empty($byFile[$file][$signatureId])) {
            $missing[] = $file . ':' . $signatureId;
        }
    }

    $transformTrace = $byFile['transform_eval.php']['taint_request_to_eval']['trace'] ?? [];
    $transformNames = [];

    foreach (($transformTrace['transforms'] ?? []) as $transform) {
        $transformNames[] = (string)($transform['name'] ?? '');
    }

    if (!empty($missing) || !in_array('base64_decode', $transformNames, true) || (($transformTrace['risk']['score'] ?? 0) !== 10)) {
        delement_antivirus_taint_smoke_fail('Taint findings are missing or incomplete', [
            'missing' => $missing,
            'signatures' => array_keys($signatures),
            'transform_trace' => $transformTrace,
            'summary' => $summary,
        ]);
    }

    echo json_encode([
        'taint' => 'ok',
        'signatures' => array_keys($signatures),
        'transform_trace' => $transformTrace,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
} finally {
    delement_antivirus_taint_smoke_remove_tree($fixtureRoot);
}
