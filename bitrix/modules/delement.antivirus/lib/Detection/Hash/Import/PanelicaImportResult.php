<?php

namespace Delement\Antivirus\Detection\Hash\Import;

class PanelicaImportResult
{
    private $status;
    private $sourceUsed;
    private $imported;
    private $skippedInvalid;
    private $skippedDuplicates;
    private $prefixesGenerated;
    private $output;
    private $warnings;
    private $error;
    private $metadata;

    public function __construct(array $data)
    {
        $this->status = (string)($data['status'] ?? 'error');
        $this->sourceUsed = (string)($data['source_used'] ?? '');
        $this->imported = (int)($data['imported'] ?? 0);
        $this->skippedInvalid = (int)($data['skipped_invalid'] ?? 0);
        $this->skippedDuplicates = (int)($data['skipped_duplicates'] ?? 0);
        $this->prefixesGenerated = (int)($data['prefixes_generated'] ?? 0);
        $this->output = isset($data['output']) && is_array($data['output']) ? $data['output'] : [];
        $this->warnings = isset($data['warnings']) && is_array($data['warnings']) ? array_values($data['warnings']) : [];
        $this->error = (string)($data['error'] ?? '');
        $this->metadata = isset($data['metadata']) && is_array($data['metadata']) ? $data['metadata'] : [];
    }

    public static function success(array $data): self
    {
        $data['status'] = 'ok';

        return new self($data);
    }

    public static function error(string $error, array $warnings = []): self
    {
        return new self([
            'status' => 'error',
            'error' => $error,
            'warnings' => $warnings,
        ]);
    }

    public function isSuccess(): bool
    {
        return $this->status === 'ok';
    }

    public function getImported(): int
    {
        return $this->imported;
    }

    public function getSourceUsed(): string
    {
        return $this->sourceUsed;
    }

    public function getWarnings(): array
    {
        return $this->warnings;
    }

    public function getOutput(): array
    {
        return $this->output;
    }

    public function getMetadata(): array
    {
        return $this->metadata;
    }

    public function getError(): string
    {
        return $this->error;
    }

    public function toArray(): array
    {
        $result = [
            'status' => $this->status,
            'source' => 'panelica',
            'source_used' => $this->sourceUsed,
            'imported' => $this->imported,
            'skipped_invalid' => $this->skippedInvalid,
            'skipped_duplicates' => $this->skippedDuplicates,
            'prefixes_generated' => $this->prefixesGenerated,
            'output' => $this->output,
            'warnings' => $this->warnings,
        ];

        if ($this->error !== '') {
            $result['error'] = $this->error;
        }

        if (!empty($this->metadata)) {
            $result['metadata'] = $this->metadata;
        }

        return $result;
    }
}
