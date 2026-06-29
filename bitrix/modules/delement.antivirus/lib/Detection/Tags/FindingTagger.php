<?php

namespace Delement\Antivirus\Detection\Tags;

use Delement\Antivirus\Detection\Finding;

class FindingTagger
{
    public function tag(Finding $finding): Finding
    {
        $data = $finding->toArray();

        return $finding->withTags($this->tagsForFindingArray($data));
    }

    public function tagsForFindingArray(array $finding): array
    {
        $category = strtolower((string)($finding['category'] ?? ''));
        $target = strtolower((string)($finding['target'] ?? ''));
        $ruleType = strtolower((string)($finding['rule_type'] ?? ''));
        $signatureId = strtolower((string)($finding['signature_id'] ?? ''));
        $tags = isset($finding['tags']) && is_array($finding['tags']) ? $finding['tags'] : [];

        if ($category === 'php_ast') {
            $tags[] = TagCatalog::ENGINE_AST;
        } elseif ($category === 'taint' || $category === 'php_taint') {
            $tags[] = TagCatalog::ENGINE_TAINT;
        } elseif ($category === 'htaccess') {
            $tags[] = TagCatalog::ENGINE_HTACCESS;
        } elseif ($category === 'entropy') {
            $tags[] = TagCatalog::ENGINE_ENTROPY;
        } elseif ($category === 'url') {
            $tags[] = TagCatalog::ENGINE_URL;
        } elseif ($category === 'hash_db') {
            $tags[] = TagCatalog::ENGINE_HASH_DB;
        } elseif ($category === 'webshell_fingerprint') {
            $tags[] = TagCatalog::ENGINE_FINGERPRINT;
        } elseif ($category === 'baseline') {
            $tags[] = TagCatalog::ENGINE_BASELINE;
        } elseif ($category === 'bitrix_db') {
            $tags[] = TagCatalog::ENGINE_BITRIX_DB;
        } elseif ($category === 'core_integrity') {
            $tags[] = TagCatalog::ENGINE_CORE_INTEGRITY;
        }

        if ($ruleType === 'regex' || $ruleType === 'path') {
            $tags[] = TagCatalog::ENGINE_REGEX;
        }

        if ($target === 'db_agent') {
            $tags[] = TagCatalog::ENTITY_DB_AGENT;
            $tags[] = TagCatalog::ENGINE_BITRIX_DB;
        } elseif ($target === 'db_event') {
            $tags[] = TagCatalog::ENTITY_DB_EVENT;
            $tags[] = TagCatalog::ENGINE_BITRIX_DB;
        } elseif ($target === 'db_template_condition') {
            $tags[] = TagCatalog::ENTITY_DB_TEMPLATE_CONDITION;
            $tags[] = TagCatalog::ENGINE_BITRIX_DB;
        } elseif ($target === 'db_trigger') {
            $tags[] = TagCatalog::ENTITY_DB_TRIGGER;
            $tags[] = TagCatalog::ENGINE_BITRIX_DB;
        }

        if (strpos($signatureId, 'dangerous_call') !== false || strpos($signatureId, 'request_to_') !== false) {
            $tags[] = TagCatalog::RISK_DANGEROUS_SINK;
        }

        if (strpos($signatureId, 'encoded') !== false || strpos($signatureId, 'base64') !== false || strpos($signatureId, 'gzinflate') !== false) {
            $tags[] = TagCatalog::RISK_ENCODED_PAYLOAD;
        }

        if (
            $category === 'taint'
            || $category === 'php_taint'
            || strpos($signatureId, 'request') !== false
            || $this->traceContainsRequestSource($finding['trace'] ?? null)
        ) {
            $tags[] = TagCatalog::RISK_REQUEST_INPUT;
        }

        if (strpos($signatureId, 'dynamic') !== false || strpos($signatureId, 'callable') !== false) {
            $tags[] = TagCatalog::RISK_DYNAMIC_CALL;
        }

        if (strpos($signatureId, 'file_put_contents') !== false || strpos($signatureId, 'fwrite') !== false || strpos($signatureId, 'file_write') !== false) {
            $tags[] = TagCatalog::RISK_FILE_WRITE;
        }

        if ($signatureId === 'htaccess_php_handler_for_static_ext') {
            $tags[] = TagCatalog::RISK_HTACCESS_HANDLER;
        }

        if ($signatureId === 'htaccess_auto_prepend_append') {
            $tags[] = TagCatalog::RISK_PERSISTENCE;
        }

        if ($category === 'webshell_fingerprint') {
            $tags[] = TagCatalog::RISK_WEBSHELL_FINGERPRINT;
        }

        if ($category === 'hash_db') {
            $tags[] = TagCatalog::RISK_KNOWN_MALWARE_HASH;
        }

        if ($category === 'entropy') {
            $tags[] = TagCatalog::RISK_ENTROPY;
        }

        if ($category === 'url') {
            $tags[] = TagCatalog::RISK_EXTERNAL_URL;
        }

        if ($category === 'url' && (strpos($signatureId, 'remote_payload_loader') !== false || strpos($signatureId, 'external_script_injection') !== false)) {
            $tags[] = TagCatalog::RISK_REMOTE_LOADER;
        }

        if ($category === 'baseline') {
            $tags[] = TagCatalog::RISK_BASELINE_CHANGE;
        }

        if ($category === 'core_integrity') {
            $tags[] = TagCatalog::RISK_MODIFIED_CORE;
        }

        return TagCatalog::normalize($tags);
    }

    private function traceContainsRequestSource($trace): bool
    {
        if (!is_array($trace)) {
            return false;
        }

        $source = isset($trace['source']) ? (string)$trace['source'] : '';

        if ($source !== '' && preg_match('/\$_(?:GET|POST|REQUEST|COOKIE)\b/i', $source) === 1) {
            return true;
        }

        foreach ($trace as $value) {
            if (is_array($value) && $this->traceContainsRequestSource($value)) {
                return true;
            }
        }

        return false;
    }
}
