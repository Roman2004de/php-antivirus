<?php

namespace Delement\Antivirus\Scanner;

use Delement\Antivirus\Detection\Finding;
use Delement\Antivirus\Detection\Severity;
use Delement\Antivirus\Detection\Verdict;
use Delement\Antivirus\Whitelist\SuppressionFingerprint;

class ScanResult
{
    private $filePath;
    private $fileHash;
    private $normalizedHash;
    private $status;
    private $score;
    private $severity;
    private $findings;
    private $action;
    private $plannedAction;
    private $error;
    private $tags = [];

    public function __construct(array $data)
    {
        $this->filePath = isset($data['file_path']) ? (string)$data['file_path'] : '';
        $this->fileHash = isset($data['file_hash']) ? (string)$data['file_hash'] : '';
        $this->normalizedHash = array_key_exists('normalized_hash', $data) && $data['normalized_hash'] !== null
            ? (string)$data['normalized_hash']
            : null;
        $this->status = isset($data['status']) ? (string)$data['status'] : Verdict::CLEAN;
        $this->score = isset($data['score']) ? (int)$data['score'] : 0;
        $this->severity = isset($data['severity']) ? (string)$data['severity'] : Severity::INFO;
        $this->findings = isset($data['findings']) && is_array($data['findings']) ? $data['findings'] : [];
        $this->action = isset($data['action']) ? (string)$data['action'] : 'report';
        $this->plannedAction = isset($data['planned_action']) ? (string)$data['planned_action'] : $this->action;
        $this->error = isset($data['error']) ? (string)$data['error'] : '';
        $this->tags = isset($data['tags']) && is_array($data['tags']) ? self::normalizeTags($data['tags']) : [];
    }

    public static function fromFindings(
        string $filePath,
        string $status,
        int $score,
        string $severity,
        array $findings,
        string $action,
        bool $dryRun,
        array $tags = [],
        ?string $normalizedHash = null,
        string $documentRoot = ''
    ): self {
        $findings = self::withFindingFingerprints($filePath, $findings, $documentRoot);

        return new self([
            'file_path' => $filePath,
            'file_hash' => self::calculateHash($filePath),
            'normalized_hash' => $normalizedHash,
            'status' => $status,
            'score' => $score,
            'severity' => $severity,
            'findings' => $findings,
            'action' => $dryRun ? 'report' : $action,
            'planned_action' => $action,
            'tags' => $tags,
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

    public function hasRiskFindings(): bool
    {
        foreach ($this->findings as $finding) {
            if ($finding instanceof Finding && $finding->getScore() > 0) {
                return true;
            }
        }

        return false;
    }

    public function getInformationalFindingsCount(): int
    {
        $count = 0;

        foreach ($this->findings as $finding) {
            if ($finding instanceof Finding && $finding->getScore() <= 0) {
                $count++;
            }
        }

        return $count;
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

    public function getTags(): array
    {
        return $this->tags;
    }

    public function withNormalizedHash(?string $normalizedHash): self
    {
        $copy = clone $this;
        $copy->normalizedHash = $normalizedHash;

        return $copy;
    }

    public function toArray(): array
    {
        return [
            'file_path' => $this->filePath,
            'file_hash' => $this->fileHash,
            'normalized_hash' => $this->normalizedHash,
            'status' => $this->status,
            'score' => $this->score,
            'severity' => $this->severity,
            'tags' => $this->tags,
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

    private static function withFindingFingerprints(string $filePath, array $findings, string $documentRoot): array
    {
        if (!class_exists(SuppressionFingerprint::class)) {
            $path = dirname(__DIR__) . '/Whitelist/SuppressionFingerprint.php';

            if (is_file($path)) {
                require_once $path;
            }
        }

        $result = [];

        foreach ($findings as $finding) {
            if (!$finding instanceof Finding) {
                continue;
            }

            $fingerprint = $finding->getFingerprint();

            if ($fingerprint === '') {
                $fingerprint = class_exists(SuppressionFingerprint::class)
                    ? SuppressionFingerprint::forFinding($filePath, $finding->toArray(), $documentRoot)
                    : hash('sha256', $filePath . "\n" . $finding->getSignatureId() . "\n" . $finding->getTarget() . "\n" . sha1($finding->getExcerpt()));
            }

            $result[] = $finding->withFingerprint($fingerprint);
        }

        return $result;
    }

    private static function normalizeTags(array $tags): array
    {
        $result = [];
        $seen = [];

        foreach ($tags as $tag) {
            $tag = strtolower(trim((string)$tag));

            if ($tag === '' || isset($seen[$tag])) {
                continue;
            }

            $result[] = $tag;
            $seen[$tag] = true;
        }

        sort($result, SORT_STRING);

        return $result;
    }
}
