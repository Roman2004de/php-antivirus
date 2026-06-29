<?php

namespace Delement\Antivirus\Scanner;

class ScanSummary
{
    private $path;
    private $startedAt;
    private $finishedAt;
    private $processedFiles = 0;
    private $foundFiles = 0;
    private $informationalFindingsTotal = 0;
    private $skippedFiles = 0;
    private $runtimeErrors = 0;
    private $results = [];

    public function __construct(string $path)
    {
        $this->path = $path;
        $this->startedAt = date('c');
    }

    public function addResult(ScanResult $result): void
    {
        $this->results[] = $result;

        if ($result->isSkipped()) {
            $this->skippedFiles++;
            return;
        }

        $this->processedFiles++;

        if ($result->isError()) {
            $this->runtimeErrors++;
            return;
        }

        $this->informationalFindingsTotal += $result->getInformationalFindingsCount();

        if ($result->hasRiskFindings()) {
            $this->foundFiles++;
        }
    }

    public function addRuntimeError(string $path, string $message): void
    {
        $this->addResult(ScanResult::error($path, $message));
    }

    public function finish(): void
    {
        $this->finishedAt = date('c');
    }

    public function toArray(): array
    {
        return [
            'path' => $this->path,
            'started_at' => $this->startedAt,
            'finished_at' => $this->finishedAt,
            'processed_files' => $this->processedFiles,
            'found_files' => $this->foundFiles,
            'informational_findings_total' => $this->informationalFindingsTotal,
            'skipped_files' => $this->skippedFiles,
            'runtime_errors' => $this->runtimeErrors,
            'results' => array_map(static function (ScanResult $result) {
                return $result->toArray();
            }, $this->results),
        ];
    }
}
