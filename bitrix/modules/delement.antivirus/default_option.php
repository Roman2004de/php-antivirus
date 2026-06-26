<?php

$delement_antivirus_default_option = [
    'scan_path' => '#DOCUMENT_ROOT#',
    'scan_profile' => 'standard',
    'profile' => 'balanced',
    'action' => 'report',
    'dry_run' => 'Y',
    'quarantine_path' => '#DOCUMENT_ROOT#/bitrix/tmp/delement.antivirus/quarantine',
    'signatures_path' => '',
    'exclude_paths' => "/bitrix/cache/\n/bitrix/managed_cache/\n/bitrix/stack_cache/\n/bitrix/html_pages/\n/upload/resize_cache/\n/bitrix/tmp/delement.antivirus/\n/bitrix/modules/delement.antivirus/",
    'batch_size' => '50',
    'max_file_size_mb' => '100',
    'enable_common_strings_prefilter' => 'Y',
    'enable_ast_analysis' => 'Y',
    'ast_max_file_size' => '1048576',
];
