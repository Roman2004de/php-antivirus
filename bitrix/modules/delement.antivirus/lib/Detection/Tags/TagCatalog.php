<?php

namespace Delement\Antivirus\Detection\Tags;

class TagCatalog
{
    public const PATH_CORE = 'path:core';
    public const PATH_LOCAL = 'path:local';
    public const PATH_UPLOAD = 'path:upload';
    public const PATH_BITRIX_MODULE = 'path:bitrix_module';
    public const PATH_LOCAL_MODULE = 'path:local_module';
    public const PATH_PHP_INTERFACE = 'path:php_interface';
    public const PATH_PUBLIC_ROOT = 'path:public_root';
    public const PATH_TMP = 'path:tmp';
    public const PATH_CACHE = 'path:cache';
    public const PATH_HIDDEN = 'path:hidden';
    public const PATH_VENDOR = 'path:vendor';

    public const ENTITY_FILE = 'entity:file';
    public const ENTITY_DB_AGENT = 'entity:db_agent';
    public const ENTITY_DB_EVENT = 'entity:db_event';
    public const ENTITY_DB_TEMPLATE_CONDITION = 'entity:db_template_condition';
    public const ENTITY_DB_TRIGGER = 'entity:db_trigger';

    public const RISK_EXECUTABLE_UPLOAD = 'risk:executable_upload';
    public const RISK_MODIFIED_CORE = 'risk:modified_core';
    public const RISK_DANGEROUS_SINK = 'risk:dangerous_sink';
    public const RISK_ENCODED_PAYLOAD = 'risk:encoded_payload';
    public const RISK_REQUEST_INPUT = 'risk:request_input';
    public const RISK_DYNAMIC_CALL = 'risk:dynamic_call';
    public const RISK_REMOTE_LOADER = 'risk:remote_loader';
    public const RISK_FILE_WRITE = 'risk:file_write';
    public const RISK_HTACCESS_HANDLER = 'risk:htaccess_handler';
    public const RISK_PERSISTENCE = 'risk:persistence';
    public const RISK_WEBSHELL_FINGERPRINT = 'risk:webshell_fingerprint';
    public const RISK_KNOWN_MALWARE_HASH = 'risk:known_malware_hash';
    public const RISK_ENTROPY = 'risk:entropy';
    public const RISK_EXTERNAL_URL = 'risk:external_url';
    public const RISK_BASELINE_CHANGE = 'risk:baseline_change';

    public const ENGINE_REGEX = 'engine:regex';
    public const ENGINE_AST = 'engine:ast';
    public const ENGINE_TAINT = 'engine:taint';
    public const ENGINE_HTACCESS = 'engine:htaccess';
    public const ENGINE_FINGERPRINT = 'engine:fingerprint';
    public const ENGINE_HASH_DB = 'engine:hash_db';
    public const ENGINE_ENTROPY = 'engine:entropy';
    public const ENGINE_URL = 'engine:url';
    public const ENGINE_BASELINE = 'engine:baseline';
    public const ENGINE_BITRIX_DB = 'engine:bitrix_db';
    public const ENGINE_CORE_INTEGRITY = 'engine:core_integrity';

    public static function normalize(array $tags): array
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

    public static function merge(array ...$tagSets): array
    {
        $merged = [];

        foreach ($tagSets as $tags) {
            foreach ($tags as $tag) {
                $merged[] = $tag;
            }
        }

        return self::normalize($merged);
    }
}
