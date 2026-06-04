<?php

use Bitrix\Main\Loader;
use Bitrix\Main\Localization\Loc;
use Delement\Antivirus\Admin\AjaxController;

define('NO_KEEP_STATISTIC', true);
define('NO_AGENT_STATISTIC', true);
define('DisableEventsCheck', true);

require_once $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/prolog_before.php';

$moduleId = 'delement.antivirus';

Loc::loadMessages(__FILE__);

$sendJson = static function (array $payload, $status = 200) {
    if (!headers_sent()) {
        http_response_code($status);
        header('Content-Type: application/json; charset=UTF-8');
    }

    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    die();
};

$normalizeErrorCode = static function ($error): string {
    $error = trim((string)$error);

    if ($error !== '' && preg_match('/^[a-z0-9_]+$/', $error)) {
        return $error;
    }

    return 'internal_error';
};

$logException = static function ($error, Throwable $exception = null) use ($moduleId) {
    if ($exception === null) {
        return;
    }

    $message = implode("\n", [
        Loc::getMessage('DELEMENT_ANTIVIRUS_AJAX_LOG_ERROR', ['#ERROR#' => (string)$error]),
        Loc::getMessage('DELEMENT_ANTIVIRUS_AJAX_LOG_EXCEPTION', ['#EXCEPTION#' => get_class($exception)]),
        Loc::getMessage('DELEMENT_ANTIVIRUS_AJAX_LOG_MESSAGE', ['#MESSAGE#' => $exception->getMessage()]),
        Loc::getMessage('DELEMENT_ANTIVIRUS_AJAX_LOG_FILE', ['#FILE#' => $exception->getFile()]),
        Loc::getMessage('DELEMENT_ANTIVIRUS_AJAX_LOG_LINE', ['#LINE#' => (string)$exception->getLine()]),
        Loc::getMessage('DELEMENT_ANTIVIRUS_AJAX_LOG_TRACE', ['#TRACE#' => $exception->getTraceAsString()]),
    ]);

    if (function_exists('AddMessage2Log')) {
        AddMessage2Log($message, $moduleId);
        return;
    }

    error_log('[' . $moduleId . '] ' . $message);
};

$sendError = static function ($error, $status = 500, Throwable $exception = null) use ($sendJson, $normalizeErrorCode, $logException) {
    $errorCode = $normalizeErrorCode($error);
    $logException($errorCode, $exception);

    $payload = [
        'success' => false,
        'status' => 'failed',
        'error' => $errorCode,
        'processed_files' => 0,
        'total_files_estimated' => 0,
        'found_total' => 0,
        'runtime_errors' => 1,
        'current_file' => '',
    ];

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
