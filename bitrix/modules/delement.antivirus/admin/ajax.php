<?php

define('NO_KEEP_STATISTIC', true);
define('NO_AGENT_STATISTIC', true);
define('DisableEventsCheck', true);

require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/prolog_before.php';

$moduleId = 'delement.antivirus';

$sendJson = static function (array $payload, $status = 200) {
    if (!headers_sent()) {
        http_response_code($status);
        header('Content-Type: application/json; charset=UTF-8');
    }

    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    die();
};

if (!$USER->IsAuthorized() || $APPLICATION->GetGroupRight($moduleId) < 'W') {
    $sendJson([
        'success' => false,
        'error' => 'access_denied',
    ], 403);
}

if (!check_bitrix_sessid()) {
    $sendJson([
        'success' => false,
        'error' => 'bad_sessid',
    ], 403);
}

$action = isset($_REQUEST['action']) ? (string)$_REQUEST['action'] : '';

if ($action === 'ping') {
    $sendJson([
        'success' => true,
        'module' => $moduleId,
        'version' => '0.0.1',
        'status' => 'skeleton_ready',
    ]);
}

$sendJson([
    'success' => false,
    'error' => 'unknown_action',
], 400);
