<?php

use Delement\Antivirus\Bitrix\Database\BitrixDb;
use Delement\Antivirus\Bitrix\Scanner\EventHandlerScanner;
use Delement\Antivirus\Cli\ScanCommand;
use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\Scanner\ScanRunService;

$vendorAutoload = __DIR__ . '/../vendor/autoload.php';

if (is_file($vendorAutoload)) {
    require_once $vendorAutoload;
}

require_once __DIR__ . '/../lib/Storage/RuntimeDirectory.php';
require_once __DIR__ . '/../lib/Support/ModuleVersion.php';
require_once __DIR__ . '/../lib/Cli/ArgvParser.php';
require_once __DIR__ . '/../lib/Cli/ScanCommand.php';
require_once __DIR__ . '/../lib/Config/ScanConfig.php';
require_once __DIR__ . '/../lib/File/FileTypeDetector.php';
require_once __DIR__ . '/../lib/File/FileReader.php';
require_once __DIR__ . '/../lib/File/FileFilter.php';
require_once __DIR__ . '/../lib/File/FileCollector.php';
require_once __DIR__ . '/../lib/Detection/Severity.php';
require_once __DIR__ . '/../lib/Detection/Verdict.php';
require_once __DIR__ . '/../lib/Detection/Finding.php';
require_once __DIR__ . '/../lib/Detection/Tags/TagCatalog.php';
require_once __DIR__ . '/../lib/Detection/Tags/PathTagger.php';
require_once __DIR__ . '/../lib/Detection/Tags/FindingTagger.php';
require_once __DIR__ . '/../lib/Detection/Tags/ResultTagger.php';
require_once __DIR__ . '/../lib/Detection/SignatureLoader.php';
require_once __DIR__ . '/../lib/Detection/RuleEngine.php';
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
require_once __DIR__ . '/../lib/Detection/Entropy/EntropyCalculator.php';
require_once __DIR__ . '/../lib/Detection/Entropy/EntropyFindingFactory.php';
require_once __DIR__ . '/../lib/Detection/Entropy/EntropyAnalyzer.php';
require_once __DIR__ . '/../lib/Detection/Url/UrlExtractor.php';
require_once __DIR__ . '/../lib/Detection/Url/SuspiciousDomainList.php';
require_once __DIR__ . '/../lib/Detection/Url/UrlFindingFactory.php';
require_once __DIR__ . '/../lib/Detection/Url/UrlAnalyzer.php';
require_once __DIR__ . '/../lib/Detection/Detector.php';
require_once __DIR__ . '/../lib/Scanner/ScanResult.php';
require_once __DIR__ . '/../lib/Scanner/ScanSummary.php';
require_once __DIR__ . '/../lib/Scanner/Scanner.php';
require_once __DIR__ . '/../lib/Scanner/ScanRunService.php';
require_once __DIR__ . '/../lib/Bitrix/Database/BitrixDb.php';
require_once __DIR__ . '/../lib/Bitrix/Resolver/ClassMethodLocator.php';
require_once __DIR__ . '/../lib/Bitrix/Resolver/EventHandlerResolver.php';
require_once __DIR__ . '/../lib/Bitrix/Scanner/BitrixDbFindingFactory.php';
require_once __DIR__ . '/../lib/Bitrix/Scanner/EventHandlerRiskAnalyzer.php';
require_once __DIR__ . '/../lib/Bitrix/Scanner/EventHandlerScanner.php';

class DelementAntivirusEventScannerSmokeDb extends BitrixDb
{
    private $eventHandlers;
    private $available;
    private $tableExists;
    private $installedModules;

    public function __construct(array $eventHandlers, bool $available = true, bool $tableExists = true, array $installedModules = [])
    {
        parent::__construct(null);
        $this->eventHandlers = $eventHandlers;
        $this->available = $available;
        $this->tableExists = $tableExists;
        $this->installedModules = $installedModules ?: [
            'main' => true,
            'iblock' => true,
            'sale' => true,
            'custom.module' => true,
        ];
    }

    public function isAvailable(): bool
    {
        return $this->available;
    }

    public function tableExists(string $tableName): bool
    {
        return $this->available && $this->tableExists && $tableName === 'b_module_to_module';
    }

    public function fetchEventHandlers(): array
    {
        return $this->eventHandlers;
    }

    public function isModuleInstalled(string $moduleId): ?bool
    {
        return isset($this->installedModules[$moduleId]) ? (bool)$this->installedModules[$moduleId] : false;
    }
}

class DelementAntivirusEventScannerSmokeRunner extends ScanRunService
{
    public $capturedConfig;

    public function __construct()
    {
    }

    public function runToCompletion(ScanConfig $config, int $createdBy = 0, callable $onStep = null): array
    {
        $this->capturedConfig = $config;

        return [
            'success' => true,
            'status' => 'finished',
            'scan_id' => 'event_cli_smoke',
            'processed_files' => 0,
            'total_files_estimated' => 0,
            'files_discovered' => 0,
            'found_total' => 0,
            'informational_findings_total' => 0,
            'bitrix_db_results_total' => 0,
            'runtime_errors' => 0,
            'report_path' => '',
        ];
    }
}

function delement_antivirus_event_smoke_fail(string $message, array $context = []): void
{
    fwrite(STDERR, $message . PHP_EOL);

    if (!empty($context)) {
        fwrite(STDERR, json_encode($context, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL);
    }

    exit(1);
}

function delement_antivirus_event_smoke_remove_tree(string $path): void
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

function delement_antivirus_event_smoke_result_by_id(array $results, string $id): array
{
    foreach ($results as $result) {
        if ((string)($result['file_path'] ?? '') === 'bitrix-db://b_module_to_module/' . $id) {
            return $result;
        }
    }

    return [];
}

function delement_antivirus_event_smoke_has_signature(array $result, string $signatureId): bool
{
    foreach ((array)($result['findings'] ?? []) as $finding) {
        if (is_array($finding) && (string)($finding['signature_id'] ?? '') === $signatureId) {
            return true;
        }
    }

    return false;
}

function delement_antivirus_event_smoke_finding(array $result, string $signatureId): array
{
    foreach ((array)($result['findings'] ?? []) as $finding) {
        if (is_array($finding) && (string)($finding['signature_id'] ?? '') === $signatureId) {
            return $finding;
        }
    }

    return [];
}

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'delement_antivirus_event_smoke_' . getmypid();
$documentRoot = $root . DIRECTORY_SEPARATOR . 'site';
$moduleRoot = $root . DIRECTORY_SEPARATOR . 'module';

delement_antivirus_event_smoke_remove_tree($root);

try {
    foreach ([
        $documentRoot . DIRECTORY_SEPARATOR . 'local' . DIRECTORY_SEPARATOR . 'php_interface',
        $documentRoot . DIRECTORY_SEPARATOR . 'local' . DIRECTORY_SEPARATOR . 'modules' . DIRECTORY_SEPARATOR . 'custom.module' . DIRECTORY_SEPARATOR . 'lib',
        $moduleRoot . DIRECTORY_SEPARATOR . 'install',
    ] as $directory) {
        if (!mkdir($directory, 0777, true) && !is_dir($directory)) {
            delement_antivirus_event_smoke_fail('Cannot create fixture directory', ['directory' => $directory]);
        }
    }

    file_put_contents($moduleRoot . DIRECTORY_SEPARATOR . 'install' . DIRECTORY_SEPARATOR . 'version.php', "<?php\n\$arModuleVersion = ['VERSION' => '0.0.4'];\n");
    file_put_contents($moduleRoot . DIRECTORY_SEPARATOR . 'default_option.php', "<?php\n\$delement_antivirus_default_option = [];\n");
    file_put_contents(
        $documentRoot . DIRECTORY_SEPARATOR . 'local' . DIRECTORY_SEPARATOR . 'php_interface' . DIRECTORY_SEPARATOR . 'init.php',
        "<?php\nclass InitEventHandler { public static function onPageStart() { eval(\$_POST['payload']); } }\n"
    );
    file_put_contents(
        $documentRoot . DIRECTORY_SEPARATOR . 'local' . DIRECTORY_SEPARATOR . 'modules' . DIRECTORY_SEPARATOR . 'custom.module' . DIRECTORY_SEPARATOR . 'lib' . DIRECTORY_SEPARATOR . 'eventhandler.php',
        "<?php\nnamespace Custom\\Module;\nclass EventHandler { public static function onLogin() { system(\$_GET['cmd']); } }\n"
    );
    $_SERVER['DOCUMENT_ROOT'] = $documentRoot;

    $eventHandlers = [
        ['ID' => '1', 'FROM_MODULE_ID' => 'main', 'MESSAGE_ID' => 'OnAfterEpilog', 'TO_MODULE_ID' => 'main', 'TO_CLASS' => 'SafeMissingHandler', 'TO_METHOD' => 'handle', 'SORT' => '100'],
        ['ID' => '2', 'FROM_MODULE_ID' => 'main', 'MESSAGE_ID' => 'OnBeforeProlog', 'TO_MODULE_ID' => 'missing.module', 'TO_CLASS' => 'Missing\\Handler', 'TO_METHOD' => 'onBeforeProlog', 'SORT' => '100'],
        ['ID' => '3', 'FROM_MODULE_ID' => 'main', 'MESSAGE_ID' => 'OnPageStart', 'TO_MODULE_ID' => 'main', 'TO_CLASS' => '', 'TO_METHOD' => 'shell_exec', 'SORT' => '100'],
        ['ID' => '4', 'FROM_MODULE_ID' => 'main', 'MESSAGE_ID' => 'OnPageStart', 'TO_MODULE_ID' => 'main', 'TO_CLASS' => 'InitEventHandler', 'TO_METHOD' => 'onPageStart', 'SORT' => '100'],
        ['ID' => '5', 'FROM_MODULE_ID' => 'main', 'MESSAGE_ID' => 'OnAfterUserLogin', 'TO_MODULE_ID' => 'custom.module', 'TO_CLASS' => 'Custom\\Module\\EventHandler', 'TO_METHOD' => 'onLogin', 'SORT' => '100'],
        ['ID' => '6', 'FROM_MODULE_ID' => 'main', 'MESSAGE_ID' => 'OnAfterUserLogin', 'TO_MODULE_ID' => 'main', 'TO_CLASS' => 'NotFoundHandler', 'TO_METHOD' => 'notFound', 'SORT' => '100'],
    ];

    $config = new ScanConfig([
        'document_root' => $documentRoot,
        'path' => $documentRoot,
        'enable_bitrix_db_scan' => 'Y',
        'scan_event_handlers' => 'Y',
        'resolve_event_handler_code' => 'Y',
        'enable_hash_db' => 'N',
        'profile' => ScanConfig::PROFILE_STRICT,
        'scan_profile' => ScanConfig::SCAN_PROFILE_DEEP,
    ]);
    $scanner = new EventHandlerScanner(new DelementAntivirusEventScannerSmokeDb($eventHandlers));
    $results = array_map(static function ($result) {
        return $result->toArray();
    }, $scanner->scan($config));

    if (!empty(delement_antivirus_event_smoke_result_by_id($results, '1'))) {
        delement_antivirus_event_smoke_fail('Safe missing handler must not create result', ['results' => $results]);
    }

    if (!empty(delement_antivirus_event_smoke_result_by_id($results, '6'))) {
        delement_antivirus_event_smoke_fail('Not found handler must not create result or fatal', ['results' => $results]);
    }

    $unknownCritical = delement_antivirus_event_smoke_result_by_id($results, '2');
    $dangerousMethod = delement_antivirus_event_smoke_result_by_id($results, '3');
    $initResolved = delement_antivirus_event_smoke_result_by_id($results, '4');
    $moduleResolved = delement_antivirus_event_smoke_result_by_id($results, '5');

    if (
        empty($unknownCritical)
        || !delement_antivirus_event_smoke_has_signature($unknownCritical, 'bitrix_event_critical_hook_unknown_module')
        || (string)($unknownCritical['findings'][0]['trace']['message_id'] ?? '') !== 'OnBeforeProlog'
    ) {
        delement_antivirus_event_smoke_fail('Critical unknown module event finding is wrong', ['result' => $unknownCritical]);
    }

    if (empty($dangerousMethod) || !delement_antivirus_event_smoke_has_signature($dangerousMethod, 'bitrix_event_dangerous_method_name')) {
        delement_antivirus_event_smoke_fail('Dangerous TO_METHOD finding is wrong', ['result' => $dangerousMethod]);
    }

    $initFileFinding = delement_antivirus_event_smoke_finding($initResolved, 'bitrix_event_handler_file_suspicious');

    if (
        empty($initResolved)
        || empty($initFileFinding)
        || strpos((string)($initFileFinding['trace']['resolved_file'] ?? ''), '/local/php_interface/init.php') === false
        || !delement_antivirus_event_smoke_has_signature($initResolved, 'bitrix_event_request_to_sink')
        || !in_array('entity:db_event', $initResolved['tags'] ?? [], true)
        || !in_array('engine:bitrix_db', $initResolved['tags'] ?? [], true)
        || !in_array('risk:persistence', $initResolved['tags'] ?? [], true)
    ) {
        delement_antivirus_event_smoke_fail('Resolved init.php event finding is wrong', ['result' => $initResolved]);
    }

    $moduleFileFinding = delement_antivirus_event_smoke_finding($moduleResolved, 'bitrix_event_handler_file_suspicious');

    if (
        empty($moduleResolved)
        || empty($moduleFileFinding)
        || strpos((string)($moduleFileFinding['trace']['resolved_file'] ?? ''), '/local/modules/custom.module/lib/eventhandler.php') === false
        || !delement_antivirus_event_smoke_has_signature($moduleResolved, 'bitrix_event_request_to_sink')
    ) {
        delement_antivirus_event_smoke_fail('Resolved local module lib event finding is wrong', ['result' => $moduleResolved]);
    }

    $noTableScanner = new EventHandlerScanner(new DelementAntivirusEventScannerSmokeDb($eventHandlers, true, false));

    if (!empty($noTableScanner->scan($config))) {
        delement_antivirus_event_smoke_fail('Missing b_module_to_module table must not create fatal/result');
    }

    $fakeRunner = new DelementAntivirusEventScannerSmokeRunner();
    $command = new ScanCommand($documentRoot, [
        'scan_path' => $documentRoot,
        'scan_profile' => ScanConfig::SCAN_PROFILE_STANDARD,
        'profile' => ScanConfig::PROFILE_BALANCED,
        'action' => ScanConfig::ACTION_REPORT,
        'dry_run' => 'Y',
        'batch_size' => '1',
        'max_file_size_mb' => '1',
    ], $moduleRoot, $fakeRunner);
    $cli = $command->execute([
        'scan.php',
        '--path=' . $documentRoot,
        '--document-root=' . $documentRoot,
        '--bitrix-db=Y',
        '--scan-events=Y',
        '--resolve-event-code=Y',
        '--json',
    ]);
    $payload = json_decode((string)$cli['stdout'], true);

    if (
        ($cli['exit_code'] ?? null) !== ScanCommand::EXIT_OK
        || !$fakeRunner->capturedConfig instanceof ScanConfig
        || !$fakeRunner->capturedConfig->isBitrixDbScanEnabled()
        || !$fakeRunner->capturedConfig->isEventHandlerScanEnabled()
        || !$fakeRunner->capturedConfig->isEventHandlerCodeResolveEnabled()
        || (($payload['scan_event_handlers'] ?? false) !== true)
        || (($payload['resolve_event_handler_code'] ?? false) !== true)
    ) {
        delement_antivirus_event_smoke_fail('CLI event flags failed', [
            'cli' => $cli,
            'payload' => $payload,
        ]);
    }

    echo json_encode([
        'bitrix_event_handler_scanner' => 'ok',
        'results' => count($results),
        'unknown_critical' => count($unknownCritical['findings']),
        'dangerous_method' => count($dangerousMethod['findings']),
        'init_resolved' => $initFileFinding['trace']['resolved_file'],
        'module_resolved' => $moduleFileFinding['trace']['resolved_file'],
        'cli_scan_events' => $payload['scan_event_handlers'],
        'cli_resolve_event_code' => $payload['resolve_event_handler_code'],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL;
} finally {
    delement_antivirus_event_smoke_remove_tree($root);
}
