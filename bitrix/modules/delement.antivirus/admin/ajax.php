<?php

use Bitrix\Main\Loader;
use Delement\Antivirus\Admin\AjaxController;

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

if (!Loader::includeModule($moduleId)) {
    $sendJson([
        'success' => false,
        'error' => 'module_not_loaded',
    ], 500);
}

$action = isset($_REQUEST['action']) ? (string)$_REQUEST['action'] : '';
$userId = is_object($USER) && method_exists($USER, 'GetID') ? (int)$USER->GetID() : 0;

try {
    $controller = new AjaxController($moduleId, (string)$_SERVER['DOCUMENT_ROOT']);
    $sendJson($controller->handle($action, $_REQUEST, $userId));
} catch (InvalidArgumentException $exception) {
    $sendJson([
        'success' => false,
        'error' => $exception->getMessage(),
    ], 400);
} catch (RuntimeException $exception) {
    $sendJson([
        'success' => false,
        'error' => $exception->getMessage(),
    ], 500);
} catch (Throwable $exception) {
    $sendJson([
        'success' => false,
        'error' => 'internal_error',
    ], 500);
}
