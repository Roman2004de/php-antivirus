<?php

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    echo 'cli_only' . PHP_EOL;
    exit(1);
}

$_SERVER['DOCUMENT_ROOT'] = realpath(__DIR__ . '/../../..');

if ($_SERVER['DOCUMENT_ROOT'] === false) {
    fwrite(STDERR, 'document_root_not_found' . PHP_EOL);
    exit(1);
}

require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/prolog_before.php';

echo json_encode(
    [
        'success' => true,
        'module' => 'delement.antivirus',
        'version' => '0.0.1',
        'status' => 'skeleton_ready',
    ],
    JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
) . PHP_EOL;

exit(0);
