<?php

$delement_antivirus_default_option = [
    'scan_path' => '#DOCUMENT_ROOT#',
    'profile' => 'balanced',
    'action' => 'report',
    'dry_run' => 'Y',
    'quarantine_path' => '#DOCUMENT_ROOT#/bitrix/modules/delement.antivirus/var/quarantine',
    'exclude_paths' => "/bitrix/cache/\n/bitrix/managed_cache/\n/bitrix/stack_cache/\n/bitrix/html_pages/\n/upload/resize_cache/\n/bitrix/modules/delement.antivirus/",
    'batch_size' => '50',
    'max_file_size_mb' => '100',
];
