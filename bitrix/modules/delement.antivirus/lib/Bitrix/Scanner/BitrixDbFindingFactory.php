<?php

namespace Delement\Antivirus\Bitrix\Scanner;

use Delement\Antivirus\Detection\Finding;
use Delement\Antivirus\Detection\Severity;
use Delement\Antivirus\Detection\Tags\TagCatalog;

class BitrixDbFindingFactory
{
    private const BASE_TAGS = [
        TagCatalog::ENTITY_DB_AGENT,
        TagCatalog::ENGINE_BITRIX_DB,
        TagCatalog::RISK_PERSISTENCE,
    ];

    public function createAgentFinding(
        string $signatureId,
        string $severity,
        int $score,
        array $agent,
        string $excerpt,
        array $tags = [],
        array $trace = []
    ): Finding {
        $score += $this->activeBonus($agent);

        return new Finding([
            'signature_id' => $signatureId,
            'name' => $signatureId,
            'category' => 'bitrix_db',
            'severity' => $severity,
            'score' => min($score, 10),
            'excerpt' => $this->excerpt($excerpt),
            'target' => 'db_agent',
            'rule_type' => 'bitrix_db',
            'file' => $this->virtualAgentPath($agent),
            'type' => 'bitrix_agent',
            'source' => 'b_agent.NAME',
            'trace' => array_merge($this->agentTrace($agent), $trace),
            'tags' => TagCatalog::merge(self::BASE_TAGS, $tags),
        ]);
    }

    public function decorateDetectorFinding(Finding $finding, array $agent): Finding
    {
        $data = $finding->toArray();
        $originalTrace = isset($data['trace']) && is_array($data['trace']) ? $data['trace'] : [];
        $data['file'] = $this->virtualAgentPath($agent);
        $data['target'] = 'db_agent';
        $data['type'] = isset($data['type']) && (string)$data['type'] !== '' ? (string)$data['type'] : 'bitrix_agent';
        $data['source'] = 'b_agent.NAME';
        $data['trace'] = array_merge($this->agentTrace($agent), [
            'detector_signature_id' => (string)($data['signature_id'] ?? ''),
            'detector_category' => (string)($data['category'] ?? ''),
            'detector_trace' => $originalTrace,
        ]);
        $data['tags'] = TagCatalog::merge(
            isset($data['tags']) && is_array($data['tags']) ? $data['tags'] : [],
            self::BASE_TAGS
        );

        return new Finding($data);
    }

    public function virtualAgentPath(array $agent): string
    {
        $id = preg_replace('/[^0-9a-zA-Z_.-]/', '_', (string)($agent['ID'] ?? ''));

        return 'bitrix-db://b_agent/' . ($id !== '' ? $id : 'unknown');
    }

    public function dangerousExecution(array $agent, string $name, string $reason): Finding
    {
        return $this->createAgentFinding(
            'bitrix_agent_dangerous_php_execution',
            Severity::CRITICAL,
            9,
            $agent,
            $name,
            [TagCatalog::RISK_DANGEROUS_SINK],
            ['reason' => $reason]
        );
    }

    public function encodedPayload(array $agent, string $name, string $marker): Finding
    {
        return $this->createAgentFinding(
            'bitrix_agent_encoded_payload',
            Severity::HIGH,
            7,
            $agent,
            $name,
            [TagCatalog::RISK_ENCODED_PAYLOAD],
            ['marker' => $marker]
        );
    }

    public function requestToSink(array $agent, string $name, string $sink): Finding
    {
        return $this->createAgentFinding(
            'bitrix_agent_request_to_sink',
            Severity::CRITICAL,
            10,
            $agent,
            $name,
            [TagCatalog::RISK_REQUEST_INPUT, TagCatalog::RISK_DANGEROUS_SINK],
            ['sink' => $sink]
        );
    }

    public function suspiciousLongCode(array $agent, string $name): Finding
    {
        return $this->createAgentFinding(
            'bitrix_agent_suspicious_long_code',
            Severity::MEDIUM,
            3,
            $agent,
            $name,
            [],
            ['name_length' => strlen($name)]
        );
    }

    public function unknownModule(array $agent, string $name, string $reason): Finding
    {
        return $this->createAgentFinding(
            'bitrix_agent_unknown_module',
            Severity::MEDIUM,
            4,
            $agent,
            $name,
            [],
            ['reason' => $reason]
        );
    }

    public function remoteLoader(array $agent, string $name, string $url = ''): Finding
    {
        return $this->createAgentFinding(
            'bitrix_agent_remote_loader',
            Severity::HIGH,
            6,
            $agent,
            $name,
            [TagCatalog::RISK_REMOTE_LOADER, TagCatalog::RISK_EXTERNAL_URL],
            ['url' => $url]
        );
    }

    public function fileWrite(array $agent, string $name, string $sink): Finding
    {
        return $this->createAgentFinding(
            'bitrix_agent_file_write',
            Severity::HIGH,
            6,
            $agent,
            $name,
            [TagCatalog::RISK_FILE_WRITE],
            ['sink' => $sink]
        );
    }

    private function agentTrace(array $agent): array
    {
        return [
            'entity' => 'bitrix_agent',
            'table' => 'b_agent',
            'id' => (string)($agent['ID'] ?? ''),
            'module_id' => (string)($agent['MODULE_ID'] ?? ''),
            'active' => (string)($agent['ACTIVE'] ?? ''),
            'next_exec' => (string)($agent['NEXT_EXEC'] ?? ''),
            'last_exec' => (string)($agent['LAST_EXEC'] ?? ''),
            'source_field' => 'NAME',
            'virtual_path' => $this->virtualAgentPath($agent),
        ];
    }

    private function activeBonus(array $agent): int
    {
        return strtoupper((string)($agent['ACTIVE'] ?? '')) === 'Y' ? 1 : 0;
    }

    private function excerpt(string $value): string
    {
        $value = trim((string)preg_replace('/\s+/', ' ', $value));

        if (strlen($value) <= 220) {
            return $value;
        }

        return substr($value, 0, 180) . '...';
    }
}
