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

$sendError = static function ($error, $status = 500, Throwable $exception = null) use ($sendJson) {
    $payload = [
        'success' => false,
        'status' => 'failed',
        'error' => $error,
        'processed_files' => 0,
        'total_files_estimated' => 0,
        'found_total' => 0,
        'runtime_errors' => 1,
        'current_file' => '',
    ];

    if ($exception !== null) {
        $payload['message'] = $exception->getMessage();
        $payload['exception'] = get_class($exception);
        $payload['file'] = $exception->getFile();
        $payload['line'] = $exception->getLine();
    }

    $sendJson($payload, $status);
};

if (!$USER->IsAuthorized() || $APPLICATION->GetGroupRight($moduleId) < 'W') {
    $sendError('access_denied', 403);
}

if (!check_bitrix_sessid()) {
    $sendError('bad_sessid', 403);
}

if (!Loader::includeModule($moduleId)) {
    $sendError('module_not_loaded', 500);
}

$action = isset($_REQUEST['action']) ? (string)$_REQUEST['action'] : '';
$userId = is_object($USER) && method_exists($USER, 'GetID') ? (int)$USER->GetID() : 0;

try {
    $controller = new AjaxController($moduleId, (string)$_SERVER['DOCUMENT_ROOT']);
    $sendJson($controller->handle($action, $_REQUEST, $userId));
} catch (InvalidArgumentException $exception) {
    $sendError($exception->getMessage(), 400, $exception);
} catch (RuntimeException $exception) {
    $sendError($exception->getMessage(), 500, $exception);
} catch (Throwable $exception) {
    $sendError('internal_error', 500, $exception);
}
