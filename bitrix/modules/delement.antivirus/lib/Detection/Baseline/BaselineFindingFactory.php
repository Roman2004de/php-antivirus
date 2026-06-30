<?php

namespace Delement\Antivirus\Detection\Baseline;

use Delement\Antivirus\Baseline\BaselineRecord;
use Delement\Antivirus\Detection\Finding;
use Delement\Antivirus\Detection\Severity;

class BaselineFindingFactory
{
    public function newFile(BaselineRecord $record): Finding
    {
        return $this->finding('baseline_new_file', 'New file since baseline', $record, Severity::MEDIUM, 3, [
            'change' => 'new',
            'current' => $record->toArray(),
        ]);
    }

    public function modifiedFile(BaselineRecord $baseline, BaselineRecord $current): Finding
    {
        return $this->finding('baseline_modified_file', 'File modified since baseline', $current, Severity::MEDIUM, 4, [
            'change' => 'modified',
            'baseline' => $baseline->toArray(),
            'current' => $current->toArray(),
            'normalized_hash_changed' => $this->normalizedHashChanged($baseline, $current),
        ]);
    }

    public function deletedFile(BaselineRecord $baseline): Finding
    {
        return $this->finding('baseline_deleted_file', 'File deleted since baseline', $baseline, Severity::MEDIUM, 3, [
            'change' => 'deleted',
            'baseline' => $baseline->toArray(),
        ]);
    }

    public function criticalPathModified(BaselineRecord $record, string $change): Finding
    {
        return $this->finding('baseline_critical_path_modified', 'Critical Bitrix path changed', $record, Severity::HIGH, 5, [
            'change' => $change,
            'critical_path' => true,
            'record' => $record->toArray(),
        ], ['risk:persistence']);
    }

    public function phpInUpload(BaselineRecord $record): Finding
    {
        return $this->finding('baseline_php_in_upload', 'Executable PHP file in upload directory', $record, Severity::CRITICAL, 9, [
            'change' => 'new',
            'record' => $record->toArray(),
        ], ['path:upload', 'risk:executable_upload']);
    }

    public function unknownFileInTools(BaselineRecord $record): Finding
    {
        return $this->finding('baseline_unknown_file_in_tools', 'New file in Bitrix admin/tools directory', $record, Severity::HIGH, 7, [
            'change' => 'new',
            'record' => $record->toArray(),
        ], ['risk:persistence']);
    }

    private function finding(
        string $signatureId,
        string $name,
        BaselineRecord $record,
        string $severity,
        int $score,
        array $trace,
        array $extraTags = []
    ): Finding {
        return new Finding([
            'signature_id' => $signatureId,
            'name' => $name,
            'category' => 'baseline',
            'severity' => $severity,
            'score' => $score,
            'offset' => null,
            'excerpt' => $record->getRelativePath() !== '' ? $record->getRelativePath() : $record->getPath(),
            'target' => 'baseline',
            'rule_type' => 'integrity',
            'file' => $record->getPath(),
            'type' => 'baseline_change',
            'source' => 'baseline',
            'confidence' => 'high',
            'trace' => $trace,
            'tags' => array_merge([
                'engine:baseline',
                'risk:baseline_change',
            ], $extraTags),
        ]);
    }

    private function normalizedHashChanged(BaselineRecord $baseline, BaselineRecord $current): ?bool
    {
        if ($baseline->getNormalizedHash() === null || $current->getNormalizedHash() === null) {
            return null;
        }

        return $baseline->getNormalizedHash() !== $current->getNormalizedHash();
    }
}
