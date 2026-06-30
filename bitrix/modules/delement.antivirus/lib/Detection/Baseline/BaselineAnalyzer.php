<?php

namespace Delement\Antivirus\Detection\Baseline;

use Delement\Antivirus\Baseline\BaselineRecord;
use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\Detection\Finding;
use Delement\Antivirus\Detection\Severity;
use Delement\Antivirus\Detection\Verdict;
use Delement\Antivirus\Scanner\ScanResult;

class BaselineAnalyzer
{
    private $factory;

    public function __construct(BaselineFindingFactory $factory = null)
    {
        $this->factory = $factory ?: new BaselineFindingFactory();
    }

    public function analyze(array $baselineRecords, array $currentRecords, ScanConfig $config): array
    {
        $baselineByKey = $this->indexRecords($baselineRecords);
        $currentByKey = $this->indexRecords($currentRecords);
        $results = [];

        foreach ($currentByKey as $key => $current) {
            if (!isset($baselineByKey[$key])) {
                $this->appendResult($results, $this->findingsForNewFile($current), $current, $config);
                continue;
            }

            $baseline = $baselineByKey[$key];

            if ($this->isModified($baseline, $current)) {
                $findings = [$this->factory->modifiedFile($baseline, $current)];
                $this->appendCriticalFindings($findings, $current, 'modified');
                $this->appendResult($results, $findings, $current, $config);
            }
        }

        foreach ($baselineByKey as $key => $baseline) {
            if (isset($currentByKey[$key])) {
                continue;
            }

            $findings = [$this->factory->deletedFile($baseline)];
            $this->appendCriticalFindings($findings, $baseline, 'deleted');
            $this->appendResult($results, $findings, $baseline, $config);
        }

        usort($results, static function (array $left, array $right) {
            return strcmp((string)($left['file_path'] ?? ''), (string)($right['file_path'] ?? ''));
        });

        return $results;
    }

    private function findingsForNewFile(BaselineRecord $record): array
    {
        $findings = [$this->factory->newFile($record)];
        $this->appendCriticalFindings($findings, $record, 'new');

        if ($this->isPhpInUpload($record)) {
            $findings[] = $this->factory->phpInUpload($record);
        }

        if ($this->isNewFileInAdminOrTools($record)) {
            $findings[] = $this->factory->unknownFileInTools($record);
        }

        return $findings;
    }

    private function appendCriticalFindings(array &$findings, BaselineRecord $record, string $change): void
    {
        if ($this->isCriticalPath($record)) {
            $findings[] = $this->factory->criticalPathModified($record, $change);
        }
    }

    private function appendResult(array &$results, array $findings, BaselineRecord $record, ScanConfig $config): void
    {
        if (empty($findings)) {
            return;
        }

        $score = 0;
        $severity = Severity::INFO;

        foreach ($findings as $finding) {
            if (!$finding instanceof Finding) {
                continue;
            }

            $score += $finding->getScore();
            $severity = Severity::max($severity, $finding->getSeverity());
        }

        $results[] = ScanResult::fromFindings(
            $record->getPath(),
            Verdict::fromScore($score, $config->getThresholds()),
            $score,
            $severity,
            $findings,
            ScanConfig::ACTION_REPORT,
            true,
            $this->resultTags($findings),
            $record->getNormalizedHash(),
            $config->getDocumentRoot()
        )->toArray();
    }

    private function resultTags(array $findings): array
    {
        $tags = [];
        $seen = [];

        foreach ($findings as $finding) {
            if (!$finding instanceof Finding) {
                continue;
            }

            foreach ($finding->getTags() as $tag) {
                $tag = strtolower(trim((string)$tag));

                if ($tag === '' || isset($seen[$tag])) {
                    continue;
                }

                $tags[] = $tag;
                $seen[$tag] = true;
            }
        }

        sort($tags, SORT_STRING);

        return $tags;
    }

    private function isModified(BaselineRecord $baseline, BaselineRecord $current): bool
    {
        if ($baseline->getSha256() !== '' && $current->getSha256() !== '' && $baseline->getSha256() !== $current->getSha256()) {
            return true;
        }

        if ($baseline->getSize() !== $current->getSize()) {
            return true;
        }

        if ($baseline->getNormalizedHash() !== null && $current->getNormalizedHash() !== null) {
            return $baseline->getNormalizedHash() !== $current->getNormalizedHash();
        }

        return false;
    }

    private function indexRecords(array $records): array
    {
        $indexed = [];

        foreach ($records as $record) {
            if (is_array($record)) {
                $record = BaselineRecord::fromArray($record);
            }

            if (!$record instanceof BaselineRecord) {
                continue;
            }

            $key = $this->recordKey($record);

            if ($key !== '') {
                $indexed[$key] = $record;
            }
        }

        return $indexed;
    }

    private function recordKey(BaselineRecord $record): string
    {
        $relativePath = $record->getRelativePath();

        if ($relativePath !== '') {
            return strtolower(str_replace('\\', '/', $relativePath));
        }

        return strtolower(str_replace('\\', '/', $record->getPath()));
    }

    private function isCriticalPath(BaselineRecord $record): bool
    {
        $path = $this->normalizedRelativePath($record);
        $basename = basename($path);

        if ($path === '/bitrix/php_interface/init.php' || $path === '/local/php_interface/init.php') {
            return true;
        }

        if ($basename === '.htaccess') {
            return true;
        }

        foreach ([
            '/bitrix/admin/',
            '/bitrix/tools/',
            '/upload/',
            '/local/modules/',
            '/bitrix/modules/',
        ] as $prefix) {
            if (strpos($path, $prefix) === 0) {
                return true;
            }
        }

        return false;
    }

    private function isPhpInUpload(BaselineRecord $record): bool
    {
        $path = $this->normalizedRelativePath($record);
        $extension = strtolower(pathinfo($path, PATHINFO_EXTENSION));

        return strpos($path, '/upload/') === 0
            && in_array($extension, ['php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht'], true);
    }

    private function isNewFileInAdminOrTools(BaselineRecord $record): bool
    {
        $path = $this->normalizedRelativePath($record);

        return strpos($path, '/bitrix/tools/') === 0
            || strpos($path, '/bitrix/admin/') === 0;
    }

    private function normalizedRelativePath(BaselineRecord $record): string
    {
        $path = $record->getRelativePath() !== '' ? $record->getRelativePath() : $record->getPath();
        $path = '/' . ltrim(str_replace('\\', '/', strtolower($path)), '/');

        return rtrim($path, '/');
    }
}
