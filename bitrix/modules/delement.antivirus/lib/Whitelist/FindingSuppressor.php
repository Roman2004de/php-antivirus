<?php

namespace Delement\Antivirus\Whitelist;

class FindingSuppressor
{
    private $store;
    private $documentRoot;

    public function __construct(SuppressionStore $store = null, string $documentRoot = '')
    {
        $this->store = $store ?: new SuppressionStore();
        $this->documentRoot = rtrim($documentRoot, '/\\');
    }

    public function suppress(array $result, array $finding, int $createdBy = 0, string $comment = ''): array
    {
        $filePath = (string)($result['file_path'] ?? '');
        $fingerprint = $this->findingFingerprint($filePath, $finding);

        return $this->store->add([
            'fingerprint' => $fingerprint,
            'scope' => 'finding',
            'file_path' => SuppressionFingerprint::normalizeRelativePath($filePath, $this->documentRoot),
            'signature_id' => (string)($finding['signature_id'] ?? ''),
            'target' => (string)($finding['target'] ?? 'content'),
            'excerpt_hash' => SuppressionFingerprint::excerptHash((string)($finding['excerpt'] ?? '')),
            'created_at' => date('c'),
            'created_by' => $createdBy,
            'comment' => $comment,
        ]);
    }

    public function filterResult(array $result): array
    {
        $findings = isset($result['findings']) && is_array($result['findings']) ? $result['findings'] : [];

        if (empty($findings)) {
            return $result;
        }

        $keptFindings = [];
        $suppressedFindings = [];
        $suppressionFingerprints = [];
        $filePath = (string)($result['file_path'] ?? '');

        foreach ($findings as $finding) {
            $finding = is_array($finding) ? $finding : [];
            $finding['fingerprint'] = $this->findingFingerprint($filePath, $finding);

            if ($this->store->has((string)$finding['fingerprint'])) {
                $suppressedFindings[] = $finding;
                $suppressionFingerprints[(string)$finding['fingerprint']] = true;
                continue;
            }

            $keptFindings[] = $finding;
        }

        $result['findings'] = $keptFindings;

        if (!empty($suppressedFindings)) {
            $result['suppression_applied'] = true;
            $result['suppressed_total'] = count($suppressedFindings);
            $result['suppressed_findings'] = $suppressedFindings;
            $result['suppression_fingerprints'] = array_keys($suppressionFingerprints);
        }

        return $result;
    }

    public function listItems(): array
    {
        return $this->store->listItems();
    }

    public function delete(string $fingerprint): bool
    {
        return $this->store->delete($fingerprint);
    }

    public function fingerprintForResultFinding(array $result, array $finding): string
    {
        return $this->findingFingerprint((string)($result['file_path'] ?? ''), $finding);
    }

    private function findingFingerprint(string $filePath, array $finding): string
    {
        $existing = strtolower(trim((string)($finding['fingerprint'] ?? '')));

        if (preg_match('/^[a-f0-9]{64}$/', $existing) === 1) {
            return $existing;
        }

        return SuppressionFingerprint::forFinding($filePath, $finding, $this->documentRoot);
    }
}
