<?php

namespace Delement\Antivirus\Detection;

use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\Detection\Tags\ResultTagger;
use Delement\Antivirus\Scanner\ScanResult;

class Detector
{
    private $ruleEngine;
    private $astAnalyzer;
    private $htaccessAnalyzer;
    private $resultTagger;

    private const AST_EXTENSIONS = [
        'php' => true,
        'php5' => true,
        'php7' => true,
        'phtml' => true,
        'module' => true,
        'include' => true,
    ];

    public function __construct(RuleEngine $ruleEngine, $astAnalyzer = null, $htaccessAnalyzer = null, ResultTagger $resultTagger = null)
    {
        $this->ruleEngine = $ruleEngine;
        $this->astAnalyzer = $astAnalyzer;
        $this->htaccessAnalyzer = $htaccessAnalyzer;
        $this->resultTagger = $resultTagger ?: $this->createResultTagger();

        if ($this->astAnalyzer === null && class_exists('Delement\\Antivirus\\Detection\\Ast\\AstAnalyzer')) {
            $className = 'Delement\\Antivirus\\Detection\\Ast\\AstAnalyzer';
            $this->astAnalyzer = new $className();
        }

        if ($this->htaccessAnalyzer === null && class_exists('Delement\\Antivirus\\Detection\\Htaccess\\HtaccessAnalyzer')) {
            $className = 'Delement\\Antivirus\\Detection\\Htaccess\\HtaccessAnalyzer';
            $this->htaccessAnalyzer = new $className();
        }
    }

    public function detect(string $filePath, iterable $chunks, ScanConfig $config): ScanResult
    {
        $findings = [];
        $seen = [];
        $astContent = '';
        $astTooLarge = false;
        $useAst = $this->shouldAnalyzeAst($filePath, $config);
        $htaccessContent = '';
        $useHtaccess = $this->shouldAnalyzeHtaccess($filePath);

        foreach ($this->ruleEngine->analyzePath($filePath, $config) as $finding) {
            $this->addFinding($findings, $seen, $finding);
        }

        foreach ($chunks as $chunk) {
            $chunk = (string)$chunk;

            foreach ($this->ruleEngine->analyzeContent((string)$chunk, $filePath, $config) as $finding) {
                $this->addFinding($findings, $seen, $finding);
            }

            if ($useAst && !$astTooLarge) {
                if (strlen($astContent) + strlen($chunk) <= $config->getAstMaxFileSize()) {
                    $astContent .= $chunk;
                } else {
                    $astTooLarge = true;
                    $astContent = '';
                }
            }

            if ($useHtaccess) {
                $htaccessContent .= $chunk;
            }
        }

        if ($useAst && !$astTooLarge && $astContent !== '' && $this->astAnalyzer !== null) {
            foreach ($this->astAnalyzer->analyze($astContent, $filePath) as $finding) {
                $this->addFinding($findings, $seen, $finding);
            }
        }

        if ($useHtaccess && $htaccessContent !== '' && $this->htaccessAnalyzer !== null) {
            foreach ($this->htaccessAnalyzer->analyze($htaccessContent, $filePath) as $finding) {
                $this->addFinding($findings, $seen, $finding);
            }
        }

        $resultTags = [];

        if ($this->resultTagger !== null) {
            $findings = $this->resultTagger->tagFindings($findings);
            $resultTags = $this->resultTagger->tagsForResult($filePath, $findings);
        }

        $score = 0;
        $severity = Severity::INFO;

        foreach ($findings as $finding) {
            $score += $finding->getScore();
            $severity = Severity::max($severity, $finding->getSeverity());
        }

        $verdict = Verdict::fromScore($score, $config->getThresholds());

        return ScanResult::fromFindings($filePath, $verdict, $score, $severity, $findings, $config->getAction(), $config->isDryRun(), $resultTags);
    }

    private function addFinding(array &$findings, array &$seen, Finding $finding): void
    {
        $key = $this->findingKey($finding);

        if ($key !== '' && isset($seen[$key])) {
            return;
        }

        $findings[] = $finding;

        if ($key !== '') {
            $seen[$key] = true;
        }
    }

    private function findingKey(Finding $finding): string
    {
        $id = $finding->getSignatureId();

        if ($id === '') {
            return '';
        }

        $offset = $finding->getOffset();
        $excerpt = $finding->getExcerpt();

        if ($offset === null && $excerpt === '') {
            return $id;
        }

        return implode(':', [
            $id,
            $finding->getTarget(),
            $finding->getRuleType(),
            $offset === null ? '-' : (string)$offset,
            sha1($excerpt),
        ]);
    }

    private function shouldAnalyzeAst(string $filePath, ScanConfig $config): bool
    {
        if (!$config->isAstAnalysisEnabled() || $this->astAnalyzer === null) {
            return false;
        }

        $extension = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));

        return isset(self::AST_EXTENSIONS[$extension]);
    }

    private function shouldAnalyzeHtaccess(string $filePath): bool
    {
        return basename($filePath) === '.htaccess' && $this->htaccessAnalyzer !== null;
    }

    private function createResultTagger()
    {
        if (!class_exists(ResultTagger::class)) {
            $tagPath = __DIR__ . '/Tags';

            foreach (['TagCatalog.php', 'PathTagger.php', 'FindingTagger.php', 'ResultTagger.php'] as $file) {
                $path = $tagPath . '/' . $file;

                if (is_file($path)) {
                    require_once $path;
                }
            }
        }

        return class_exists(ResultTagger::class) ? new ResultTagger() : null;
    }
}
