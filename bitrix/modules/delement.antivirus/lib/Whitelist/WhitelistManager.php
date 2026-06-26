<?php

namespace Delement\Antivirus\Whitelist;

use Delement\Antivirus\Detection\Severity;
use Delement\Antivirus\Detection\Tags\ResultTagger;
use Delement\Antivirus\Detection\Verdict;
use Delement\Antivirus\Storage\RuntimeDirectory;
use RuntimeException;

class WhitelistManager
{
    public const TYPE_PATH = 'path';
    public const TYPE_PATH_REGEX = 'path_regex';
    public const TYPE_HASH = 'hash';
    public const TYPE_SIGNATURE = 'signature_id';
    public const TYPE_FILE_SIGNATURE = 'file_signature';
    public const TYPE_FINDING_SUPPRESSION = 'finding_suppression';

    private $storagePath;
    private $rulesPath;
    private $resultTagger;
    private $findingSuppressor;
    private $documentRoot;

    public function __construct(string $moduleRoot = null, ResultTagger $resultTagger = null, string $documentRoot = '', FindingSuppressor $findingSuppressor = null)
    {
        $this->loadSuppressionClasses();
        $moduleRoot = $moduleRoot ?: dirname(__DIR__, 2);
        $this->documentRoot = $documentRoot !== '' ? rtrim($documentRoot, '/\\') : rtrim((string)($_SERVER['DOCUMENT_ROOT'] ?? ''), '/\\');
        $this->storagePath = RuntimeDirectory::resolve($moduleRoot, 'whitelist');
        $this->rulesPath = $this->storagePath . DIRECTORY_SEPARATOR . 'rules.json';
        $this->resultTagger = $resultTagger;
        $this->findingSuppressor = $findingSuppressor ?: new FindingSuppressor(new SuppressionStore($moduleRoot), $this->documentRoot);

        if ($this->resultTagger === null && class_exists(ResultTagger::class)) {
            $this->resultTagger = new ResultTagger();
        }
    }

    public function addRule(string $type, array $data, int $createdBy = 0): array
    {
        $rule = $this->buildRule($type, $data, $createdBy);
        $rules = $this->listRules();

        foreach ($rules as $existingRule) {
            if (!empty($existingRule['active']) && ($existingRule['fingerprint'] ?? '') === $rule['fingerprint']) {
                return $existingRule;
            }
        }

        $rules[] = $rule;
        $this->saveRules($rules);

        return $rule;
    }

    public function listRules(): array
    {
        if (!is_file($this->rulesPath)) {
            return [];
        }

        $data = json_decode((string)file_get_contents($this->rulesPath), true);

        if (!is_array($data)) {
            throw new RuntimeException('whitelist_rules_corrupted');
        }

        return isset($data['rules']) && is_array($data['rules']) ? $data['rules'] : [];
    }

    public function listFindingSuppressions(): array
    {
        return $this->findingSuppressor->listItems();
    }

    public function suppressFinding(array $result, array $finding, int $createdBy = 0, string $comment = ''): array
    {
        return $this->findingSuppressor->suppress($result, $finding, $createdBy, $comment);
    }

    public function deleteFindingSuppression(string $fingerprint): bool
    {
        return $this->findingSuppressor->delete($fingerprint);
    }

    public function removeRule(string $id): void
    {
        $this->deactivateRule($id);
    }

    public function activateRule(string $id): void
    {
        $this->setRuleActive($id, true);
    }

    public function deactivateRule(string $id): void
    {
        $this->setRuleActive($id, false);
    }

    public function deleteRule(string $id): void
    {
        $rules = $this->listRules();
        $filteredRules = [];
        $found = false;

        foreach ($rules as $rule) {
            if ((string)($rule['id'] ?? '') === $id) {
                $found = true;
                continue;
            }

            $filteredRules[] = $rule;
        }

        if (!$found) {
            throw new RuntimeException('whitelist_rule_not_found');
        }

        $this->saveRules($filteredRules);
    }

    private function setRuleActive(string $id, bool $active): void
    {
        $rules = $this->listRules();
        $found = false;

        foreach ($rules as &$rule) {
            if ((string)($rule['id'] ?? '') === $id) {
                $rule['active'] = $active;
                if ($active) {
                    unset($rule['disabled_at']);
                    $rule['activated_at'] = date('c');
                } else {
                    $rule['disabled_at'] = date('c');
                }
                $found = true;
                break;
            }
        }
        unset($rule);

        if (!$found) {
            throw new RuntimeException('whitelist_rule_not_found');
        }

        $this->saveRules($rules);
    }

    public function filterResult(array $result, array $thresholds): array
    {
        $findings = isset($result['findings']) && is_array($result['findings']) ? $result['findings'] : [];

        if (empty($findings)) {
            return $result;
        }

        $result['findings'] = $this->ensureFindingFingerprints($result, $findings);
        $rules = array_values(array_filter($this->listRules(), static function (array $rule) {
            return !empty($rule['active']);
        }));
        $changed = false;

        if (!empty($rules)) {
            $keptFindings = [];
            $ignoredFindings = [];
            $matchedRuleIds = [];

            foreach ($result['findings'] as $finding) {
                $finding = is_array($finding) ? $finding : [];
                $matchedRule = $this->matchFinding($result, $finding, $rules);

                if ($matchedRule === null) {
                    $keptFindings[] = $finding;
                    continue;
                }

                $finding['whitelist_rule_id'] = (string)$matchedRule['id'];
                $finding['whitelist_rule_type'] = (string)$matchedRule['type'];
                $ignoredFindings[] = $finding;
                $matchedRuleIds[(string)$matchedRule['id']] = true;
            }

            if (!empty($ignoredFindings)) {
                $result['findings'] = $keptFindings;
                $result['whitelist_applied'] = true;
                $result['whitelisted_total'] = count($ignoredFindings);
                $result['whitelisted_findings'] = $ignoredFindings;
                $result['whitelist_rule_ids'] = array_keys($matchedRuleIds);
                $changed = true;
            }
        }

        $beforeSuppressCount = count($result['findings']);
        $result = $this->findingSuppressor->filterResult($result);

        if (count($result['findings']) !== $beforeSuppressCount) {
            $changed = true;
        }

        if ($changed) {
            $this->recalculateResult($result, $thresholds);
            $this->recalculateTags($result);
        }

        return $result;
    }

    private function buildRule(string $type, array $data, int $createdBy): array
    {
        $type = trim($type);

        if (!in_array($type, $this->getAllowedTypes(), true)) {
            throw new RuntimeException('whitelist_type_invalid');
        }

        $rule = [
            'id' => $this->createRuleId(),
            'type' => $type,
            'active' => true,
            'created_at' => date('c'),
            'created_by' => $createdBy,
            'comment' => isset($data['comment']) ? trim((string)$data['comment']) : '',
        ];

        if ($type === self::TYPE_PATH) {
            $path = $this->normalizePathValue(isset($data['path']) ? (string)$data['path'] : '');
            $rule['path'] = $path;
            $rule['fingerprint'] = $this->fingerprint([$type, $path]);
        } elseif ($type === self::TYPE_PATH_REGEX) {
            $pattern = trim(isset($data['pattern']) ? (string)$data['pattern'] : '');
            $this->validateRegex($pattern);
            $rule['pattern'] = $pattern;
            $rule['fingerprint'] = $this->fingerprint([$type, $pattern]);
        } elseif ($type === self::TYPE_HASH) {
            $hash = $this->normalizeHash(isset($data['hash']) ? (string)$data['hash'] : '');
            $rule['hash'] = $hash;
            $rule['fingerprint'] = $this->fingerprint([$type, $hash]);
        } elseif ($type === self::TYPE_SIGNATURE) {
            $signatureId = $this->normalizeSignatureId(isset($data['signature_id']) ? (string)$data['signature_id'] : '');
            $rule['signature_id'] = $signatureId;
            $rule['fingerprint'] = $this->fingerprint([$type, $signatureId]);
        } else {
            $signatureId = $this->normalizeSignatureId(isset($data['signature_id']) ? (string)$data['signature_id'] : '');
            $path = $this->normalizePathValue(isset($data['path']) ? (string)$data['path'] : '');
            $hash = isset($data['hash']) ? trim((string)$data['hash']) : '';

            $rule['path'] = $path;
            $rule['hash'] = $hash !== '' ? $this->normalizeHash($hash) : '';
            $rule['signature_id'] = $signatureId;
            $rule['fingerprint'] = $this->fingerprint([$type, $path, $rule['hash'], $signatureId]);
        }

        return $rule;
    }

    private function loadSuppressionClasses(): void
    {
        $basePath = __DIR__;

        foreach (['SuppressionFingerprint.php', 'SuppressionStore.php', 'FindingSuppressor.php'] as $file) {
            $className = __NAMESPACE__ . '\\' . basename($file, '.php');

            if (!class_exists($className)) {
                $path = $basePath . DIRECTORY_SEPARATOR . $file;

                if (is_file($path)) {
                    require_once $path;
                }
            }
        }
    }

    public function filterSuppressedFindings(array $result, array $thresholds): array
    {
        $findings = isset($result['findings']) && is_array($result['findings']) ? $result['findings'] : [];

        if (empty($findings)) {
            return $result;
        }

        $result['findings'] = $this->ensureFindingFingerprints($result, $findings);
        $beforeSuppressCount = count($result['findings']);
        $result = $this->findingSuppressor->filterResult($result);

        if (count($result['findings']) !== $beforeSuppressCount) {
            $this->recalculateResult($result, $thresholds);
            $this->recalculateTags($result);
        }

        return $result;
    }

    private function ensureFindingFingerprints(array $result, array $findings): array
    {
        $preparedFindings = [];

        foreach ($findings as $finding) {
            $finding = is_array($finding) ? $finding : [];
            $finding['fingerprint'] = $this->findingSuppressor->fingerprintForResultFinding($result, $finding);
            $preparedFindings[] = $finding;
        }

        return $preparedFindings;
    }

    private function matchFinding(array $result, array $finding, array $rules): ?array
    {
        $filePath = $this->normalizePath((string)($result['file_path'] ?? ''));
        $fileHash = strtolower((string)($result['file_hash'] ?? ''));
        $signatureId = (string)($finding['signature_id'] ?? '');

        foreach ($rules as $rule) {
            $type = (string)($rule['type'] ?? '');

            if ($type === self::TYPE_PATH && $filePath === (string)($rule['path'] ?? '')) {
                return $rule;
            }

            if ($type === self::TYPE_PATH_REGEX && $this->matchesRegex((string)($rule['pattern'] ?? ''), $filePath)) {
                return $rule;
            }

            if ($type === self::TYPE_HASH && $fileHash !== '' && $fileHash === (string)($rule['hash'] ?? '')) {
                return $rule;
            }

            if ($type === self::TYPE_SIGNATURE && $signatureId !== '' && $signatureId === (string)($rule['signature_id'] ?? '')) {
                return $rule;
            }

            if ($type === self::TYPE_FILE_SIGNATURE && $signatureId !== '' && $signatureId === (string)($rule['signature_id'] ?? '')) {
                $rulePath = (string)($rule['path'] ?? '');
                $ruleHash = (string)($rule['hash'] ?? '');

                if (($ruleHash !== '' && $fileHash === $ruleHash) || ($rulePath !== '' && $filePath === $rulePath)) {
                    return $rule;
                }
            }
        }

        return null;
    }

    private function recalculateResult(array &$result, array $thresholds): void
    {
        $findings = isset($result['findings']) && is_array($result['findings']) ? $result['findings'] : [];
        $score = 0;
        $severity = Severity::INFO;

        foreach ($findings as $finding) {
            $score += isset($finding['score']) ? (int)$finding['score'] : 0;
            $severity = Severity::max($severity, isset($finding['severity']) ? (string)$finding['severity'] : Severity::INFO);
        }

        $result['score'] = $score;
        $result['severity'] = $severity;
        $result['status'] = Verdict::fromScore($score, $thresholds);
    }

    private function recalculateTags(array &$result): void
    {
        if ($this->resultTagger === null) {
            return;
        }

        $result = $this->resultTagger->tagResultArray($result);
    }

    private function saveRules(array $rules): void
    {
        $payload = [
            'format' => 'delement.antivirus.whitelist',
            'format_version' => 1,
            'updated_at' => date('c'),
            'rules' => array_values($rules),
        ];

        $json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        if ($json === false) {
            throw new RuntimeException('whitelist_rules_encode_failed');
        }

        if (file_put_contents($this->rulesPath, $json, LOCK_EX) === false) {
            throw new RuntimeException('whitelist_rules_save_failed');
        }

        @chmod($this->rulesPath, 0600);
    }

    private function getAllowedTypes(): array
    {
        return [
            self::TYPE_PATH,
            self::TYPE_PATH_REGEX,
            self::TYPE_HASH,
            self::TYPE_SIGNATURE,
            self::TYPE_FILE_SIGNATURE,
        ];
    }

    private function createRuleId(): string
    {
        return date('Ymd_His') . '_' . bin2hex(random_bytes(6));
    }

    private function normalizePathValue(string $path): string
    {
        $path = trim($path);

        if ($path === '' || strpos($path, "\0") !== false) {
            throw new RuntimeException('whitelist_path_invalid');
        }

        return $this->normalizePath($path);
    }

    private function normalizePath(string $path): string
    {
        return str_replace('\\', '/', strtolower(rtrim($path, '/\\')));
    }

    private function normalizeHash(string $hash): string
    {
        $hash = strtolower(trim($hash));

        if (!preg_match('/^[a-f0-9]{64}$/', $hash)) {
            throw new RuntimeException('whitelist_hash_invalid');
        }

        return $hash;
    }

    private function normalizeSignatureId(string $signatureId): string
    {
        $signatureId = trim($signatureId);

        if ($signatureId === '' || !preg_match('/^[a-zA-Z0-9_.:-]+$/', $signatureId)) {
            throw new RuntimeException('whitelist_signature_invalid');
        }

        return $signatureId;
    }

    private function validateRegex(string $pattern): void
    {
        if ($pattern === '' || @preg_match($pattern, '') === false) {
            throw new RuntimeException('whitelist_regex_invalid');
        }
    }

    private function matchesRegex(string $pattern, string $value): bool
    {
        return $pattern !== '' && @preg_match($pattern, $value) === 1;
    }

    private function fingerprint(array $parts): string
    {
        return hash('sha256', implode("\n", array_map('strval', $parts)));
    }
}
