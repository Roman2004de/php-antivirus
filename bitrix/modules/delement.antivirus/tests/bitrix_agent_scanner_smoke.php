<?php

use Delement\Antivirus\Bitrix\Database\BitrixDb;
use Delement\Antivirus\Bitrix\Scanner\AgentScanner;
use Delement\Antivirus\Bitrix\Scanner\BitrixDatabaseScanService;
use Delement\Antivirus\Bitrix\Scanner\BitrixDbFindingFactory;
use Delement\Antivirus\Bitrix\Scanner\VirtualCodeScanner;
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
require_once __DIR__ . '/../lib/Scanner/ScanResult.php';
require_once __DIR__ . '/../lib/Scanner/ScanRunService.php';
require_once __DIR__ . '/../lib/Bitrix/Database/BitrixDb.php';
require_once __DIR__ . '/../lib/Bitrix/Scanner/BitrixDbFindingFactory.php';
require_once __DIR__ . '/../lib/Bitrix/Scanner/VirtualCodeScanner.php';
require_once __DIR__ . '/../lib/Bitrix/Scanner/AgentScanner.php';
require_once __DIR__ . '/../lib/Bitrix/Scanner/BitrixDatabaseScanService.php';

class DelementAntivirusAgentScannerSmokeDb extends BitrixDb
{
    private $agents;
    private $available;
    private $installedModules;

    public function __construct(array $agents, bool $available = true, array $installedModules = ['main' => true])
    {
        parent::__construct(null);
        $this->agents = $agents;
        $this->available = $available;
        $this->installedModules = $installedModules;
    }

    public function isAvailable(): bool
    {
        return $this->available;
    }

    public function tableExists(string $tableName): bool
    {
        return $this->available && $tableName === 'b_agent';
    }

    public function fetchAgents(): array
    {
        return $this->agents;
    }

    public function isModuleInstalled(string $moduleId): ?bool
    {
        return isset($this->installedModules[$moduleId]) ? (bool)$this->installedModules[$moduleId] : false;
    }
}

class DelementAntivirusAgentScannerSmokeRunner extends ScanRunService
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
            'scan_id' => 'agent_cli_smoke',
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

function delement_antivirus_agent_smoke_fail(string $message, array $context = []): void
{
    fwrite(STDERR, $message . PHP_EOL);

    if (!empty($context)) {
        fwrite(STDERR, json_encode($context, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL);
    }

    exit(1);
}

function delement_antivirus_agent_smoke_remove_tree(string $path): void
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

function delement_antivirus_agent_smoke_result_by_id(array $results, string $id): array
{
    foreach ($results as $result) {
        $path = (string)($result['file_path'] ?? '');

        if ($path === 'bitrix-db://b_agent/' . $id) {
            return $result;
        }
    }

    return [];
}

function delement_antivirus_agent_smoke_has_signature(array $result, string $signatureId): bool
{
    foreach ((array)($result['findings'] ?? []) as $finding) {
        if (is_array($finding) && (string)($finding['signature_id'] ?? '') === $signatureId) {
            return true;
        }
    }

    return false;
}

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'delement_antivirus_agent_smoke_' . getmypid();
$documentRoot = $root . DIRECTORY_SEPARATOR . 'site';
$moduleRoot = $root . DIRECTORY_SEPARATOR . 'module';

delement_antivirus_agent_smoke_remove_tree($root);

try {
    foreach ([$documentRoot, $moduleRoot . DIRECTORY_SEPARATOR . 'install'] as $directory) {
        if (!mkdir($directory, 0777, true) && !is_dir($directory)) {
            delement_antivirus_agent_smoke_fail('Cannot create fixture directory', ['directory' => $directory]);
        }
    }

    file_put_contents($moduleRoot . DIRECTORY_SEPARATOR . 'install' . DIRECTORY_SEPARATOR . 'version.php', "<?php\n\$arModuleVersion = ['VERSION' => '0.0.4'];\n");
    file_put_contents($moduleRoot . DIRECTORY_SEPARATOR . 'default_option.php', "<?php\n\$delement_antivirus_default_option = [];\n");
    file_put_contents($documentRoot . DIRECTORY_SEPARATOR . 'clean.php', "<?php\n");
    $_SERVER['DOCUMENT_ROOT'] = $documentRoot;

    $agents = [
        ['ID' => '1', 'MODULE_ID' => 'main', 'NAME' => '\\Vendor\\Module\\Agent::run();', 'ACTIVE' => 'Y', 'NEXT_EXEC' => '2026-07-01 12:00:00'],
        ['ID' => '2', 'MODULE_ID' => 'main', 'NAME' => "eval(base64_decode('cGhwaW5mbygpOw=='));", 'ACTIVE' => 'Y', 'NEXT_EXEC' => '2026-07-01 12:05:00'],
        ['ID' => '3', 'MODULE_ID' => 'main', 'NAME' => "system(\$_GET['cmd']);", 'ACTIVE' => 'Y', 'NEXT_EXEC' => '2026-07-01 12:10:00'],
        ['ID' => '4', 'MODULE_ID' => 'main', 'NAME' => "file_put_contents(\$_SERVER['DOCUMENT_ROOT'].'/upload/a.php', '<?php echo 1;');", 'ACTIVE' => 'N', 'NEXT_EXEC' => '2026-07-01 12:15:00'],
        ['ID' => '5', 'MODULE_ID' => 'missing.module', 'NAME' => '\\Missing\\Module\\Agent::run();', 'ACTIVE' => 'Y', 'NEXT_EXEC' => '2026-07-01 12:20:00'],
    ];

    $config = new ScanConfig([
        'document_root' => $documentRoot,
        'path' => $documentRoot,
        'enable_bitrix_db_scan' => 'Y',
        'scan_agents' => 'Y',
        'enable_hash_db' => 'N',
        'profile' => ScanConfig::PROFILE_STRICT,
        'scan_profile' => ScanConfig::SCAN_PROFILE_DEEP,
    ]);

    $scanner = new AgentScanner(new DelementAntivirusAgentScannerSmokeDb($agents));
    $results = array_map(static function ($result) {
        return $result->toArray();
    }, $scanner->scan($config));

    if (!empty(delement_antivirus_agent_smoke_result_by_id($results, '1'))) {
        delement_antivirus_agent_smoke_fail('Clean agent must not create result', ['results' => $results]);
    }

    $encoded = delement_antivirus_agent_smoke_result_by_id($results, '2');
    $requestSink = delement_antivirus_agent_smoke_result_by_id($results, '3');
    $fileWrite = delement_antivirus_agent_smoke_result_by_id($results, '4');
    $unknownModule = delement_antivirus_agent_smoke_result_by_id($results, '5');

    if (
        empty($encoded)
        || !delement_antivirus_agent_smoke_has_signature($encoded, 'bitrix_agent_encoded_payload')
        || !delement_antivirus_agent_smoke_has_signature($encoded, 'bitrix_agent_dangerous_php_execution')
        || !in_array('entity:db_agent', $encoded['tags'] ?? [], true)
        || !in_array('engine:bitrix_db', $encoded['tags'] ?? [], true)
        || !in_array('risk:persistence', $encoded['tags'] ?? [], true)
    ) {
        delement_antivirus_agent_smoke_fail('Encoded/eval agent findings are wrong', ['encoded' => $encoded]);
    }

    if (
        empty($requestSink)
        || !delement_antivirus_agent_smoke_has_signature($requestSink, 'bitrix_agent_request_to_sink')
        || (string)($requestSink['findings'][0]['trace']['id'] ?? '') !== '3'
    ) {
        delement_antivirus_agent_smoke_fail('Request-to-sink agent finding is wrong', ['request_sink' => $requestSink]);
    }

    if (empty($fileWrite) || !delement_antivirus_agent_smoke_has_signature($fileWrite, 'bitrix_agent_file_write')) {
        delement_antivirus_agent_smoke_fail('File-write agent finding is wrong', ['file_write' => $fileWrite]);
    }

    if (empty($unknownModule) || !delement_antivirus_agent_smoke_has_signature($unknownModule, 'bitrix_agent_unknown_module')) {
        delement_antivirus_agent_smoke_fail('Unknown module agent finding is wrong', ['unknown_module' => $unknownModule]);
    }

    $unavailableScanner = new AgentScanner(new DelementAntivirusAgentScannerSmokeDb($agents, false));

    if (!empty($unavailableScanner->scan($config))) {
        delement_antivirus_agent_smoke_fail('Unavailable Bitrix DB must not create fatal/result');
    }

    $service = new BitrixDatabaseScanService($scanner);
    $serviceResults = $service->scan($config);

    if (count($serviceResults) !== count($results) || !is_array($serviceResults[0] ?? null)) {
        delement_antivirus_agent_smoke_fail('BitrixDatabaseScanService must return result arrays', ['service_results' => $serviceResults]);
    }

    $fakeRunner = new DelementAntivirusAgentScannerSmokeRunner();
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
        '--scan-agents=Y',
        '--json',
    ]);
    $payload = json_decode((string)$cli['stdout'], true);

    if (
        ($cli['exit_code'] ?? null) !== ScanCommand::EXIT_OK
        || !$fakeRunner->capturedConfig instanceof ScanConfig
        || !$fakeRunner->capturedConfig->isBitrixDbScanEnabled()
        || !$fakeRunner->capturedConfig->isAgentScanEnabled()
        || (($payload['enable_bitrix_db_scan'] ?? false) !== true)
        || (($payload['scan_agents'] ?? false) !== true)
    ) {
        delement_antivirus_agent_smoke_fail('CLI Bitrix DB flags failed', [
            'cli' => $cli,
            'payload' => $payload,
        ]);
    }

    echo json_encode([
        'bitrix_agent_scanner' => 'ok',
        'results' => count($results),
        'encoded_agent' => count($encoded['findings']),
        'request_sink_agent' => count($requestSink['findings']),
        'file_write_agent' => count($fileWrite['findings']),
        'unknown_module_agent' => count($unknownModule['findings']),
        'cli_bitrix_db' => $payload['enable_bitrix_db_scan'],
        'cli_scan_agents' => $payload['scan_agents'],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL;
} finally {
    delement_antivirus_agent_smoke_remove_tree($root);
}
