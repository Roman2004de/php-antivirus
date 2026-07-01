<?php

namespace Delement\Antivirus\Bitrix\Scanner;

use Delement\Antivirus\Detection\Finding;
use Delement\Antivirus\Detection\Severity;
use Delement\Antivirus\Detection\Tags\TagCatalog;

class BitrixDbFindingFactory
{
    private const AGENT_TAGS = [
        TagCatalog::ENTITY_DB_AGENT,
        TagCatalog::ENGINE_BITRIX_DB,
        TagCatalog::RISK_PERSISTENCE,
    ];
    private const EVENT_TAGS = [
        TagCatalog::ENTITY_DB_EVENT,
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
            'tags' => TagCatalog::merge(self::AGENT_TAGS, $tags),
        ]);
    }

    public function createEventFinding(
        string $signatureId,
        string $severity,
        int $score,
        array $eventHandler,
        string $excerpt,
        array $tags = [],
        array $trace = []
    ): Finding {
        return new Finding([
            'signature_id' => $signatureId,
            'name' => $signatureId,
            'category' => 'bitrix_db',
            'severity' => $severity,
            'score' => min($score, 10),
            'excerpt' => $this->excerpt($excerpt),
            'target' => 'db_event',
            'rule_type' => 'bitrix_db',
            'file' => $this->virtualEventPath($eventHandler),
            'type' => 'bitrix_event_handler',
            'source' => 'b_module_to_module',
            'trace' => array_merge($this->eventTrace($eventHandler), $trace),
            'tags' => TagCatalog::merge(self::EVENT_TAGS, $tags),
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
            self::AGENT_TAGS
        );

        return new Finding($data);
    }

    public function virtualAgentPath(array $agent): string
    {
        $id = preg_replace('/[^0-9a-zA-Z_.-]/', '_', (string)($agent['ID'] ?? ''));

        return 'bitrix-db://b_agent/' . ($id !== '' ? $id : 'unknown');
    }

    public function virtualEventPath(array $eventHandler): string
    {
        $id = preg_replace('/[^0-9a-zA-Z_.-]/', '_', (string)($eventHandler['ID'] ?? ''));

        return 'bitrix-db://b_module_to_module/' . ($id !== '' ? $id : 'unknown');
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

    public function eventDangerousMethodName(array $eventHandler, string $reason): Finding
    {
        return $this->createEventFinding(
            'bitrix_event_dangerous_method_name',
            Severity::HIGH,
            7,
            $eventHandler,
            $this->eventExcerpt($eventHandler),
            [TagCatalog::RISK_DANGEROUS_SINK],
            ['risk_reason' => $reason]
        );
    }

    public function eventCriticalHookUnknownModule(array $eventHandler, string $reason, bool $criticalEvent): Finding
    {
        return $this->createEventFinding(
            'bitrix_event_critical_hook_unknown_module',
            $criticalEvent ? Severity::HIGH : Severity::MEDIUM,
            $criticalEvent ? 7 : 4,
            $eventHandler,
            $this->eventExcerpt($eventHandler),
            [],
            ['risk_reason' => $reason, 'critical_event' => $criticalEvent]
        );
    }

    public function eventHandlerFileSuspicious(array $eventHandler, string $resolvedFile, array $detectorFindings): Finding
    {
        return $this->createEventFinding(
            'bitrix_event_handler_file_suspicious',
            $this->maxDetectorSeverity($detectorFindings),
            $this->detectorScore($detectorFindings),
            $eventHandler,
            $this->eventExcerpt($eventHandler),
            [],
            [
                'risk_reason' => 'resolved_handler_file_suspicious',
                'resolved_file' => $resolvedFile,
                'detector_findings_total' => count($detectorFindings),
                'detector_signatures' => $this->detectorSignatures($detectorFindings),
            ]
        );
    }

    public function eventDynamicCallable(array $eventHandler, string $reason): Finding
    {
        return $this->createEventFinding(
            'bitrix_event_dynamic_callable',
            Severity::HIGH,
            6,
            $eventHandler,
            $this->eventExcerpt($eventHandler),
            [TagCatalog::RISK_DYNAMIC_CALL],
            ['risk_reason' => $reason]
        );
    }

    public function eventEmptyModule(array $eventHandler): Finding
    {
        return $this->createEventFinding(
            'bitrix_event_empty_module',
            Severity::MEDIUM,
            4,
            $eventHandler,
            $this->eventExcerpt($eventHandler),
            [],
            ['risk_reason' => 'empty_to_module_id']
        );
    }

    public function eventRequestToSink(array $eventHandler, string $sink, string $resolvedFile = ''): Finding
    {
        $trace = [
            'risk_reason' => 'request_to_sink',
            'sink' => $sink,
        ];

        if ($resolvedFile !== '') {
            $trace['resolved_file'] = $resolvedFile;
        }

        return $this->createEventFinding(
            'bitrix_event_request_to_sink',
            Severity::CRITICAL,
            10,
            $eventHandler,
            $this->eventExcerpt($eventHandler),
            [TagCatalog::RISK_REQUEST_INPUT, TagCatalog::RISK_DANGEROUS_SINK],
            $trace
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

    private function eventTrace(array $eventHandler): array
    {
        return [
            'entity' => 'bitrix_event_handler',
            'table' => 'b_module_to_module',
            'id' => (string)($eventHandler['ID'] ?? ''),
            'from_module_id' => (string)($eventHandler['FROM_MODULE_ID'] ?? ''),
            'message_id' => (string)($eventHandler['MESSAGE_ID'] ?? ''),
            'to_module_id' => (string)($eventHandler['TO_MODULE_ID'] ?? ''),
            'to_class' => (string)($eventHandler['TO_CLASS'] ?? ''),
            'to_method' => (string)($eventHandler['TO_METHOD'] ?? ''),
            'sort' => (string)($eventHandler['SORT'] ?? ''),
            'virtual_path' => $this->virtualEventPath($eventHandler),
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

    private function eventExcerpt(array $eventHandler): string
    {
        return trim(implode(' ', array_filter([
            (string)($eventHandler['FROM_MODULE_ID'] ?? ''),
            (string)($eventHandler['MESSAGE_ID'] ?? ''),
            (string)($eventHandler['TO_MODULE_ID'] ?? ''),
            (string)($eventHandler['TO_CLASS'] ?? ''),
            (string)($eventHandler['TO_METHOD'] ?? ''),
        ], static function ($value) {
            return $value !== '';
        })));
    }

    private function maxDetectorSeverity(array $findings): string
    {
        $severity = Severity::INFO;

        foreach ($findings as $finding) {
            if (is_array($finding)) {
                $severity = Severity::max($severity, (string)($finding['severity'] ?? Severity::INFO));
            }
        }

        return $severity;
    }

    private function detectorScore(array $findings): int
    {
        $score = 0;

        foreach ($findings as $finding) {
            if (is_array($finding)) {
                $score += max(0, (int)($finding['score'] ?? 0));
            }
        }

        return min(10, max(1, $score));
    }

    private function detectorSignatures(array $findings): array
    {
        $signatures = [];
        $seen = [];

        foreach ($findings as $finding) {
            if (!is_array($finding)) {
                continue;
            }

            $signatureId = (string)($finding['signature_id'] ?? '');

            if ($signatureId === '' || isset($seen[$signatureId])) {
                continue;
            }

            $signatures[] = $signatureId;
            $seen[$signatureId] = true;
        }

        return $signatures;
    }
}
