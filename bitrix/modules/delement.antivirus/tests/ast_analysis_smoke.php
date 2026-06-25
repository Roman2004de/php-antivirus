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

function delement_antivirus_ast_smoke_remove_tree(string $path): void
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

function delement_antivirus_ast_smoke_fail(string $message, array $context = []): void
{
    fwrite(STDERR, $message . PHP_EOL);

    if (!empty($context)) {
        fwrite(STDERR, json_encode($context, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    }

    exit(1);
}

if (!class_exists('PhpParser\\ParserFactory')) {
    delement_antivirus_ast_smoke_fail('nikic/php-parser is not available');
}

$fixtureRoot = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'delement_antivirus_ast_smoke_' . getmypid();
delement_antivirus_ast_smoke_remove_tree($fixtureRoot);

try {
    if (!mkdir($fixtureRoot, 0777, true) && !is_dir($fixtureRoot)) {
        delement_antivirus_ast_smoke_fail('Cannot create fixture directory');
    }

    $fixtures = [
        'eval_post.php' => "<?php\neval(\$_POST['x']);\n",
        'system_from_get.php' => "<?php\n\$a = \$_GET['cmd'];\nsystem(\$a);\n",
        'dynamic_assert.php' => "<?php\n\$f = 'assert';\n\$f(\$_REQUEST['x']);\n",
        'dynamic_concat.php' => "<?php\n\$func = 'ev' . 'al';\n\$func(\$payload);\n",
        'encoded_chain.php' => "<?php\neval(gzinflate(base64_decode(\$_POST['x'])));\n",
        'include_request.php' => "<?php\ninclude \$_GET['page'];\n",
        'no_open_tag.module' => "popen(\$_POST['x']);\n",
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
    $signatures = [];
    $metadataErrors = [];

    foreach ($summary['results'] as $result) {
        foreach ($result['findings'] as $finding) {
            $id = (string)($finding['signature_id'] ?? '');

            if (strpos($id, 'php_ast_') === 0) {
                $signatures[$id] = true;

                if (
                    (string)($finding['file'] ?? '') !== (string)($result['file_path'] ?? '')
                    || (int)($finding['line'] ?? 0) < 1
                    || (string)($finding['type'] ?? '') !== 'ast'
                    || (string)($finding['source'] ?? '') !== 'ast'
                ) {
                    $metadataErrors[] = [
                        'file' => $result['file_path'] ?? '',
                        'finding' => $finding,
                    ];
                }
            }
        }
    }

    $expected = [
        'php_ast_dangerous_call_eval',
        'php_ast_dangerous_call_system',
        'php_ast_dynamic_function_call',
        'php_ast_encoded_execution_chain',
        'php_ast_dangerous_call_include',
        'php_ast_dangerous_call_popen',
    ];
    $missing = [];

    foreach ($expected as $id) {
        if (empty($signatures[$id])) {
            $missing[] = $id;
        }
    }

    if (!empty($missing) || !empty($metadataErrors)) {
        delement_antivirus_ast_smoke_fail('AST findings are missing', [
            'missing' => $missing,
            'metadata_errors' => $metadataErrors,
            'signatures' => array_keys($signatures),
            'summary' => $summary,
        ]);
    }

    echo json_encode([
        'ast' => 'ok',
        'signatures' => array_keys($signatures),
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
} finally {
    delement_antivirus_ast_smoke_remove_tree($fixtureRoot);
}
