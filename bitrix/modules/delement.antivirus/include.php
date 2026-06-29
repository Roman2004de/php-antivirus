<?php

use Bitrix\Main\Loader;

if (!defined('B_PROLOG_INCLUDED') || B_PROLOG_INCLUDED !== true) {
    die();
}

if (!defined('DELEMENT_ANTIVIRUS_MODULE_ID')) {
    define('DELEMENT_ANTIVIRUS_MODULE_ID', 'delement.antivirus');
}

$vendorAutoload = __DIR__ . '/vendor/autoload.php';

if (is_file($vendorAutoload)) {
    require_once $vendorAutoload;
}

Loader::registerAutoLoadClasses(
    DELEMENT_ANTIVIRUS_MODULE_ID,
    [
        'Delement\\Antivirus\\Admin\\AjaxController' => 'lib/Admin/AjaxController.php',
        'Delement\\Antivirus\\Cli\\ArgvParser' => 'lib/Cli/ArgvParser.php',
        'Delement\\Antivirus\\Cli\\ScanCommand' => 'lib/Cli/ScanCommand.php',
        'Delement\\Antivirus\\Config\\ScanConfig' => 'lib/Config/ScanConfig.php',
        'Delement\\Antivirus\\Detection\\Detector' => 'lib/Detection/Detector.php',
        'Delement\\Antivirus\\Detection\\Ast\\AstAnalyzer' => 'lib/Detection/Ast/AstAnalyzer.php',
        'Delement\\Antivirus\\Detection\\Ast\\AstContext' => 'lib/Detection/Ast/AstContext.php',
        'Delement\\Antivirus\\Detection\\Ast\\AstFindingFactory' => 'lib/Detection/Ast/AstFindingFactory.php',
        'Delement\\Antivirus\\Detection\\Ast\\AstParseResult' => 'lib/Detection/Ast/AstParseResult.php',
        'Delement\\Antivirus\\Detection\\Ast\\DangerousCallDetector' => 'lib/Detection/Ast/DangerousCallDetector.php',
        'Delement\\Antivirus\\Detection\\Ast\\DynamicCallDetector' => 'lib/Detection/Ast/DynamicCallDetector.php',
        'Delement\\Antivirus\\Detection\\Ast\\EncodedPayloadDetector' => 'lib/Detection/Ast/EncodedPayloadDetector.php',
        'Delement\\Antivirus\\Detection\\Ast\\NodeCollector' => 'lib/Detection/Ast/NodeCollector.php',
        'Delement\\Antivirus\\Detection\\Ast\\PhpAstParser' => 'lib/Detection/Ast/PhpAstParser.php',
        'Delement\\Antivirus\\Detection\\Entropy\\EntropyAnalyzer' => 'lib/Detection/Entropy/EntropyAnalyzer.php',
        'Delement\\Antivirus\\Detection\\Entropy\\EntropyCalculator' => 'lib/Detection/Entropy/EntropyCalculator.php',
        'Delement\\Antivirus\\Detection\\Entropy\\EntropyFindingFactory' => 'lib/Detection/Entropy/EntropyFindingFactory.php',
        'Delement\\Antivirus\\Detection\\Hash\\HashDatabase' => 'lib/Detection/Hash/HashDatabase.php',
        'Delement\\Antivirus\\Detection\\Hash\\HashFindingFactory' => 'lib/Detection/Hash/HashFindingFactory.php',
        'Delement\\Antivirus\\Detection\\Hash\\HashPrefixIndex' => 'lib/Detection/Hash/HashPrefixIndex.php',
        'Delement\\Antivirus\\Detection\\Hash\\KnownMalwareHashAnalyzer' => 'lib/Detection/Hash/KnownMalwareHashAnalyzer.php',
        'Delement\\Antivirus\\Detection\\Finding' => 'lib/Detection/Finding.php',
        'Delement\\Antivirus\\Detection\\RuleEngine' => 'lib/Detection/RuleEngine.php',
        'Delement\\Antivirus\\Detection\\Severity' => 'lib/Detection/Severity.php',
        'Delement\\Antivirus\\Detection\\SignatureLoader' => 'lib/Detection/SignatureLoader.php',
        'Delement\\Antivirus\\Detection\\Tags\\FindingTagger' => 'lib/Detection/Tags/FindingTagger.php',
        'Delement\\Antivirus\\Detection\\Tags\\PathTagger' => 'lib/Detection/Tags/PathTagger.php',
        'Delement\\Antivirus\\Detection\\Tags\\ResultTagger' => 'lib/Detection/Tags/ResultTagger.php',
        'Delement\\Antivirus\\Detection\\Tags\\TagCatalog' => 'lib/Detection/Tags/TagCatalog.php',
        'Delement\\Antivirus\\Detection\\Verdict' => 'lib/Detection/Verdict.php',
        'Delement\\Antivirus\\Detection\\Taint\\TaintAnalyzer' => 'lib/Detection/Taint/TaintAnalyzer.php',
        'Delement\\Antivirus\\Detection\\Taint\\TaintFindingFactory' => 'lib/Detection/Taint/TaintFindingFactory.php',
        'Delement\\Antivirus\\Detection\\Taint\\TaintPropagator' => 'lib/Detection/Taint/TaintPropagator.php',
        'Delement\\Antivirus\\Detection\\Taint\\TaintSinkDetector' => 'lib/Detection/Taint/TaintSinkDetector.php',
        'Delement\\Antivirus\\Detection\\Taint\\TaintSourceDetector' => 'lib/Detection/Taint/TaintSourceDetector.php',
        'Delement\\Antivirus\\Detection\\Taint\\TaintTrace' => 'lib/Detection/Taint/TaintTrace.php',
        'Delement\\Antivirus\\Detection\\Htaccess\\HtaccessAnalyzer' => 'lib/Detection/Htaccess/HtaccessAnalyzer.php',
        'Delement\\Antivirus\\Detection\\Htaccess\\HtaccessFindingFactory' => 'lib/Detection/Htaccess/HtaccessFindingFactory.php',
        'Delement\\Antivirus\\Detection\\Htaccess\\HtaccessRule' => 'lib/Detection/Htaccess/HtaccessRule.php',
        'Delement\\Antivirus\\Detection\\Url\\SuspiciousDomainList' => 'lib/Detection/Url/SuspiciousDomainList.php',
        'Delement\\Antivirus\\Detection\\Url\\UrlAnalyzer' => 'lib/Detection/Url/UrlAnalyzer.php',
        'Delement\\Antivirus\\Detection\\Url\\UrlExtractor' => 'lib/Detection/Url/UrlExtractor.php',
        'Delement\\Antivirus\\Detection\\Url\\UrlFindingFactory' => 'lib/Detection/Url/UrlFindingFactory.php',
        'Delement\\Antivirus\\File\\FileCollector' => 'lib/File/FileCollector.php',
        'Delement\\Antivirus\\File\\FileFilter' => 'lib/File/FileFilter.php',
        'Delement\\Antivirus\\File\\FileReader' => 'lib/File/FileReader.php',
        'Delement\\Antivirus\\File\\FileTypeDetector' => 'lib/File/FileTypeDetector.php',
        'Delement\\Antivirus\\Quarantine\\QuarantineManager' => 'lib/Quarantine/QuarantineManager.php',
        'Delement\\Antivirus\\Report\\JsonReportWriter' => 'lib/Report/JsonReportWriter.php',
        'Delement\\Antivirus\\Report\\ReportManager' => 'lib/Report/ReportManager.php',
        'Delement\\Antivirus\\Scanner\\ScanActionApplier' => 'lib/Scanner/ScanActionApplier.php',
        'Delement\\Antivirus\\Scanner\\Scanner' => 'lib/Scanner/Scanner.php',
        'Delement\\Antivirus\\Scanner\\ScanResult' => 'lib/Scanner/ScanResult.php',
        'Delement\\Antivirus\\Scanner\\ScanRunService' => 'lib/Scanner/ScanRunService.php',
        'Delement\\Antivirus\\Scanner\\ScanSessionStore' => 'lib/Scanner/ScanSessionStore.php',
        'Delement\\Antivirus\\Scanner\\ScanSummary' => 'lib/Scanner/ScanSummary.php',
        'Delement\\Antivirus\\Storage\\RuntimeDirectory' => 'lib/Storage/RuntimeDirectory.php',
        'Delement\\Antivirus\\Support\\ModuleVersion' => 'lib/Support/ModuleVersion.php',
        'Delement\\Antivirus\\Whitelist\\FindingSuppressor' => 'lib/Whitelist/FindingSuppressor.php',
        'Delement\\Antivirus\\Whitelist\\SuppressionFingerprint' => 'lib/Whitelist/SuppressionFingerprint.php',
        'Delement\\Antivirus\\Whitelist\\SuppressionStore' => 'lib/Whitelist/SuppressionStore.php',
        'Delement\\Antivirus\\Whitelist\\WhitelistManager' => 'lib/Whitelist/WhitelistManager.php',
    ]
);
