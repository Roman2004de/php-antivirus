<?php

namespace Delement\Antivirus\Scanner;

use Delement\Antivirus\Detection\Finding;
use Delement\Antivirus\Detection\Severity;
use Delement\Antivirus\Detection\Verdict;

class ScanResult
{
    private $filePath;
    private $fileHash;
    private $status;
    private $score;
    private $severity;
    private $findings;
    private $action;
    private $plannedAction;
    private $error;

    public function __construct(array $data)
    {
        $this->filePath = isset($data['file_path']) ? (string)$data['file_path'] : '';
        $this->fileHash = isset($data['file_hash']) ? (string)$data['file_hash'] : '';
        $this->status = isset($data['status']) ? (string)$data['status'] : Verdict::CLEAN;
        $this->score = isset($data['score']) ? (int)$data['score'] : 0;
        $this->severity = isset($data['severity']) ? (string)$data['severity'] : Severity::INFO;
        $this->findings = isset($data['findings']) && is_array($data['findings']) ? $data['findings'] : [];
        $this->action = isset($data['action']) ? (string)$data['action'] : 'report';
        $this->plannedAction = isset($data['planned_action']) ? (string)$data['planned_action'] : $this->action;
        $this->error = isset($data['error']) ? (string)$data['error'] : '';
    }

    public static function fromFindings(
        string $filePath,
        string $status,
        int $score,
        string $severity,
        array $findings,
        string $action,
        bool $dryRun
    ): self {
        return new self([
            'file_path' => $filePath,
            'file_hash' => self::calculateHash($filePath),
            'status' => $status,
            'score' => $score,
            'severity' => $severity,
            'findings' => $findings,
            'action' => $dryRun ? 'report' : $action,
            'planned_action' => $action,
        ]);
    }

    public static function skipped(string $filePath, string $reason): self
    {
        return new self([
            'file_path' => $filePath,
            'status' => Verdict::SKIPPED,
            'severity' => Severity::INFO,
            'error' => $reason,
        ]);
    }

    public static function error(string $filePath, string $message): self
    {
        return new self([
            'file_path' => $filePath,
            'status' => Verdict::ERROR,
            'severity' => Severity::LOW,
            'error' => $message,
        ]);
    }

    public function hasFindings(): bool
    {
        return !empty($this->findings);
    }

    public function isError(): bool
    {
        return $this->status === Verdict::ERROR;
    }

    public function isSkipped(): bool
    {
        return $this->status === Verdict::SKIPPED;
    }

    public function getStatus(): string
    {
        return $this->status;
    }

    public function toArray(): array
    {
        return [
            'file_path' => $this->filePath,
            'file_hash' => $this->fileHash,
            'status' => $this->status,
            'score' => $this->score,
            'severity' => $this->severity,
            'findings' => array_map(static function (Finding $finding) {
                return $finding->toArray();
            }, $this->findings),
            'action' => $this->action,
            'planned_action' => $this->plannedAction,
            'error' => $this->error,
        ];
    }

    private static function calculateHash(string $filePath): string
    {
        if (!is_file($filePath) || !is_readable($filePath)) {
            return '';
        }

        $hash = @hash_file('sha256', $filePath);

        return $hash === false ? '' : $hash;
    }
}
