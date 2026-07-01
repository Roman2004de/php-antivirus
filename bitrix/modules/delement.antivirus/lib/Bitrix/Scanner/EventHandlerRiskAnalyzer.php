<?php

namespace Delement\Antivirus\Bitrix\Scanner;

use Delement\Antivirus\Bitrix\Database\BitrixDb;
use Delement\Antivirus\Detection\Finding;

class EventHandlerRiskAnalyzer
{
    private const CRITICAL_EVENTS = [
        'onpagestart' => true,
        'onbeforeprolog' => true,
        'onprolog' => true,
        'onepilog' => true,
        'onbeforeuserlogin' => true,
        'onafteruserlogin' => true,
        'onbeforeuserregister' => true,
        'onafteruserregister' => true,
        'onbeforeiblockelementadd' => true,
        'onbeforeiblockelementupdate' => true,
        'onsaleordersaved' => true,
        'onbeforeeventsend' => true,
        'onbeforemailsend' => true,
    ];

    private $db;
    private $factory;

    public function __construct(BitrixDb $db = null, BitrixDbFindingFactory $factory = null)
    {
        $this->db = $db ?: new BitrixDb();
        $this->factory = $factory ?: new BitrixDbFindingFactory();
    }

    public function analyze(array $eventHandler): array
    {
        $findings = [];
        $seen = [];
        $toMethod = trim((string)($eventHandler['TO_METHOD'] ?? ''));
        $toClass = trim((string)($eventHandler['TO_CLASS'] ?? ''));
        $toModuleId = trim((string)($eventHandler['TO_MODULE_ID'] ?? ''));
        $isCriticalEvent = $this->isCriticalEvent((string)($eventHandler['MESSAGE_ID'] ?? ''));

        if ($toModuleId === '') {
            $this->addFinding($findings, $seen, $this->factory->eventEmptyModule($eventHandler));
        } elseif (!$this->isSafeModuleId($toModuleId)) {
            $this->addFinding($findings, $seen, $this->factory->eventCriticalHookUnknownModule($eventHandler, 'invalid_to_module_id', $isCriticalEvent));
        } else {
            $installed = $this->db->isModuleInstalled($toModuleId);

            if ($installed === false) {
                $this->addFinding($findings, $seen, $this->factory->eventCriticalHookUnknownModule($eventHandler, 'module_not_installed', $isCriticalEvent));
            }
        }

        if ($toMethod !== '' && preg_match('/\b(eval|assert|system|exec|shell_exec|passthru|proc_open)\b/i', $toMethod, $match) === 1) {
            $reason = strtolower((string)$match[1]);

            if ($toClass === '') {
                $reason .= '_without_class';
            }

            $this->addFinding($findings, $seen, $this->factory->eventDangerousMethodName($eventHandler, $reason));
        }

        if ($this->looksDynamicCallable($toClass, $toMethod)) {
            $this->addFinding($findings, $seen, $this->factory->eventDynamicCallable($eventHandler, 'dynamic_callable'));
        }

        if (
            preg_match('/\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b/i', $toMethod) === 1
            && preg_match('/\b(eval|assert|system|exec|shell_exec|passthru|proc_open|popen|include|include_once|require|require_once|call_user_func|call_user_func_array)\b/i', $toMethod, $match) === 1
        ) {
            $this->addFinding($findings, $seen, $this->factory->eventRequestToSink($eventHandler, strtolower((string)$match[1])));
        }

        return $findings;
    }

    public function isCriticalEvent(string $messageId): bool
    {
        return isset(self::CRITICAL_EVENTS[strtolower(trim($messageId))]);
    }

    private function looksDynamicCallable(string $toClass, string $toMethod): bool
    {
        $callable = $toClass . '::' . $toMethod;

        if (preg_match('/[$\[\]{}]/', $callable) === 1) {
            return true;
        }

        if (stripos($toMethod, 'call_user_func') !== false || stripos($toMethod, 'create_function') !== false) {
            return true;
        }

        return strpos($toMethod, '->') !== false || substr_count($toMethod, '::') > 0;
    }

    private function addFinding(array &$findings, array &$seen, Finding $finding): void
    {
        $signatureId = $finding->getSignatureId();

        if ($signatureId !== '' && isset($seen[$signatureId])) {
            return;
        }

        $findings[] = $finding;
        $seen[$signatureId] = true;
    }

    private function isSafeModuleId(string $moduleId): bool
    {
        return preg_match('/^[a-zA-Z0-9_.-]+$/', $moduleId) === 1;
    }
}
